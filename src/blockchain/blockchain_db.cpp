#include <bts/config.hpp>
#include <bts/blockchain/trx_validation_state.hpp>
#include <bts/blockchain/blockchain_db.hpp>
#include <bts/blockchain/blockchain_market_db.hpp>
#include <bts/blockchain/asset.hpp>
#include <leveldb/db.h>
#include <bts/db/level_pod_map.hpp>
#include <bts/db/level_map.hpp>
#include <fc/io/enum_type.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/io/raw.hpp>
#include <fc/interprocess/mmap_struct.hpp>

#include <fc/filesystem.hpp>
#include <fc/log/logger.hpp>
#include <fc/io/json.hpp>

#include <algorithm>
#include <sstream>


struct trx_stat
{
   uint16_t trx_idx;
   bts::blockchain::trx_eval eval;
};
// sort with highest fees first
bool operator < ( const trx_stat& a, const trx_stat& b )
{
  return a.eval.fees.amount > b.eval.fees.amount;
}
FC_REFLECT( trx_stat, (trx_idx)(eval) )

namespace bts { namespace blockchain {
    namespace ldb = leveldb;
    namespace detail  
    { 
      
      // TODO: .01 BTC update private members to use _member naming convention
      class blockchain_db_impl
      {
         public:
            blockchain_db_impl(){}

            //std::unique_ptr<ldb::DB> blk_id2num;  // maps blocks to unique IDs
            bts::db::level_map<block_id_type,uint32_t>          blk_id2num;
            bts::db::level_map<uint160,trx_num>                 trx_id2num;
            bts::db::level_map<trx_num,meta_trx>                meta_trxs;
            bts::db::level_map<uint32_t,block_header>           blocks;
            bts::db::level_map<uint32_t,std::vector<uint160> >  block_trxs; 

            market_db                                           _market_db;

            /** cache this information because it is required in many calculations  */
            trx_block                                           head_block;
            block_id_type                                       head_block_id;

            void mark_spent( const output_reference& o, const trx_num& intrx, uint16_t in )
            {
               auto tid    = trx_id2num.fetch( o.trx_hash );
               meta_trx   mtrx   = meta_trxs.fetch( tid );
               FC_ASSERT( mtrx.meta_outputs.size() > o.output_idx );

               mtrx.meta_outputs[o.output_idx].trx_id    = intrx;
               mtrx.meta_outputs[o.output_idx].input_num = in;

               meta_trxs.store( tid, mtrx );
               remove_market_orders( o );
            }


            void remove_market_orders( const output_reference& o )
            {
               auto trx_out = get_output( o );
               if( trx_out.claim_func == claim_by_bid )
               {
                  auto cbb = trx_out.as<claim_by_bid_output>();
                  market_order order( cbb.ask_price, o );
                  _market_db.remove_bid( order );
                  _market_db.remove_ask( order );
               }

               if( trx_out.claim_func == claim_by_long )
               {
                  auto cbl = trx_out.as<claim_by_long_output>();
                  market_order order( cbl.ask_price, o );
                  _market_db.remove_bid( order );
               }
            }


            trx_output get_output( const output_reference& ref )
            { try {
               auto tid    = trx_id2num.fetch( ref.trx_hash );
               meta_trx   mtrx   = meta_trxs.fetch( tid );
               FC_ASSERT( mtrx.outputs.size() > ref.output_idx );
               return mtrx.outputs[ref.output_idx];
            } FC_RETHROW_EXCEPTIONS( warn, "", ("ref",ref) ) }
            
            /**
             *   Stores a transaction and updates the spent status of all 
             *   outputs doing one last check to make sure they are unspent.
             */
            void store( const signed_transaction& t, const trx_num& tn )
            {
               ilog( "trxid: ${id}   ${tn}\n\n  ${trx}\n\n", ("id",t.id())("tn",tn)("trx",t) );

               trx_id2num.store( t.id(), tn ); 
               meta_trxs.store( tn, meta_trx(t) );

               for( uint16_t i = 0; i < t.inputs.size(); ++i )
               {
                  mark_spent( t.inputs[i].output_ref, tn, i ); 
               }
               
               for( uint16_t i = 0; i < t.outputs.size(); ++i )
               {
                  if( t.outputs[i].claim_func == claim_by_bid )
                  {
                     claim_by_bid_output cbb = t.outputs[i].as<claim_by_bid_output>();
                     if( cbb.is_bid(t.outputs[i].unit) )
                     {
                        elog( "Insert Bid: ${bid}", ("bid",market_order(cbb.ask_price, output_reference( t.id(), i )) ) );
                        _market_db.insert_bid( market_order(cbb.ask_price, output_reference( t.id(), i )) );
                     }
                     else
                     {
                        elog( "Insert Ask: ${bid}", ("bid",market_order(cbb.ask_price, output_reference( t.id(), i )) ) );
                        _market_db.insert_ask( market_order(cbb.ask_price, output_reference( t.id(), i )) );
                     }
                  }
                  else if( t.outputs[i].claim_func == claim_by_long )
                  {
                    auto cbl = t.outputs[i].as<claim_by_long_output>();
                    elog( "Insert Short Ask: ${bid}", ("bid",market_order(cbl.ask_price, output_reference( t.id(), i )) ) );
                    _market_db.insert_bid( market_order(cbl.ask_price, output_reference( t.id(), i )) );
                  }
               }
            }

            void store( const trx_block& b )
            {
                std::vector<uint160> trxs_ids;
                for( uint16_t t = 0; t < b.trxs.size(); ++t )
                {
                   store( b.trxs[t], trx_num( b.block_num, t) );
                   trxs_ids.push_back( b.trxs[t].id() );
                }
                head_block    = b;
                head_block_id = b.id();

                blocks.store( b.block_num, b );
                block_trxs.store( b.block_num, trxs_ids );
            }

            /**
             *  Pushes a new transaction into matched that pairs all bids/asks for a single quote/base pair
             */
            void match_orders( std::vector<signed_transaction>& matched,  asset::type quote, asset::type base )
            { try {
               ilog( "match orders.." );
               auto asks = _market_db.get_asks( quote, base );
               auto bids = _market_db.get_bids( quote, base );
               wlog( "asks: ${asks}", ("asks",asks) );
               wlog( "bids: ${bids}", ("bids",bids) );

               fc::optional<trx_output>             ask_change;    // stores a claim_by_bid or claim_by_long
               fc::optional<trx_output>             bid_change;    // stores a claim_by_bid

               address                              bid_payout_address; // current bid owner
               address                              ask_payout_address;

               signed_transaction market_trx;
               market_trx.timestamp = fc::time_point::now();

               const uint64_t zero = 0ull;
               asset pay_asker( zero, quote );
               asset pay_bidder( zero, base );
               asset loan_amount( zero, quote );
               asset collateral_amount(zero,base);
               asset bidder_change(zero,quote); // except for longs?
               asset asker_change(zero,base);


               /** asks are sorted from low to high, so we start
                * with the lowest ask, and check to see if there are
                * any bids that are greaterthan or equal to the ask, if
                * there are then either the full bid or full ask will be
                * filled.  If the full bid is filled, then move on to the
                * next bid, and save the leftover ask.  If the left over
                * ask is filled, then move to the next ask.
                *
                * When there are no more pairs that can be matched, exit
                * the loop and any partial payouts are made.  
                */
               auto ask_itr = asks.begin();
               auto bid_itr = bids.rbegin();
               trx_output working_ask;
               trx_output working_bid;

               if( ask_itr != asks.end() ) working_ask = get_output( ask_itr->location );
               if( bid_itr != bids.rend() ) working_bid = get_output( bid_itr->location );

               bool has_change = false;

               while( ask_itr != asks.end() && 
                      bid_itr != bids.rend()    )
               { 
                 // asset      working_ask_tmp_amount; // store fractional working ask amounts here..
                  
                  /*
                  if( ask_change ) {  working_ask = *ask_change;                         }
                  else             {  working_ask = get_output( ask_itr->location );  
                                      working_ask_tmp_amount = working_ask.get_amount();  }

                  if( bid_change ) {  working_bid = *bid_change;                      }
                  else             {  working_bid = get_output( bid_itr->location );  }
                  */

                  claim_by_bid_output ask_claim = working_ask.as<claim_by_bid_output>();

                  wlog( "working bid: ${b}", ("b", working_bid ) );
                  wlog( "working ask: ${a}", ("a", working_ask ) );

                  ask_payout_address = ask_claim.pay_address;

                  if( working_bid.claim_func == claim_by_long )
                  {
                     auto long_claim = working_bid.as<claim_by_long_output>();
                     if( long_claim.ask_price < ask_claim.ask_price )
                     {
                        ilog( "\n\n                                  BID ${BID}  >>>>   ASK ${ASK}\n\n", ("BID",long_claim.ask_price)("ASK",ask_claim.ask_price) );
                        break; // exit the while loop, no more trades can occur
                     }
                     has_change = true;
                     bid_payout_address = long_claim.pay_address;

                     // for the purposes of shorts and longs, one asset type is BTS and the other
                     // is one of the BitAssets which I will just call 'usd' for clairty.
                     // The bids are an offer to take a short position which means they have an input
                     // of BTS but are really offering USD to buy BTS... they BTS purchased with this
                     // "new" USD is then placed into the collateral.

                     asset bid_amount_bts = working_bid.get_amount(); // * long_claim.ask_price;
                     asset bid_amount_usd = bid_amount_bts * long_claim.ask_price;

                     asset ask_amount_bts = working_ask.get_amount(); // * long_claim.ask_price;
                     asset ask_amount_usd = ask_amount_bts * ask_claim.ask_price;

                     ilog( "ask_usd ${ask_usd}   bid_usd ${bid_usd}", ("ask_usd",ask_amount_usd)("bid_usd",bid_amount_usd) );
                     ilog( "ask_bts ${ask_bts}   bid_bts ${bid_bts}", ("ask_bts",ask_amount_bts)("bid_bts",bid_amount_bts) );


                     if( ask_amount_usd < bid_amount_usd )
                     { // then we have filled the ask
                         pay_asker         += ask_amount_usd;
                         loan_amount       += ask_amount_usd;
                         collateral_amount += ask_amount_bts +  ask_amount_usd * long_claim.ask_price;
                         ilog( "bid amount bts ${bid_bts}  - ${pay_asker} * ${price} = ${result}",
                               ("bid_bts",bid_amount_bts)("pay_asker",pay_asker)("price",long_claim.ask_price)("result",pay_asker*long_claim.ask_price) );
                         bidder_change     = bid_amount_bts - (ask_amount_usd * long_claim.ask_price);

                        // ask_change.reset();
                         working_ask.amount = 0;
                         // TODO: trunctate here??? 
                         working_bid.amount = bidder_change.get_rounded_amount();
                        // bid_change       = working_bid;

                         market_trx.inputs.push_back( ask_itr->location );
                         if( pay_asker.amount > static_cast<uint64_t>(0ull) )
                            market_trx.outputs.push_back( trx_output( claim_by_signature_output( ask_claim.pay_address ), pay_asker) );
                         pay_asker = asset(static_cast<uint64_t>(0ull),pay_asker.unit);
                         ++ask_itr;
                         if( ask_itr != asks.end() )  working_ask = get_output( ask_itr->location );
                     }
                     else // we have filled the bid (short sell) 
                     {
                         pay_asker         += bid_amount_usd;
                         loan_amount       += bid_amount_usd;
                         collateral_amount += bid_amount_bts + (bid_amount_usd * ask_claim.ask_price);
                         ilog( "ask_amount_bts ${bid_bts}  - ${loan_amount} * ${price} = ${result}",
                               ("bid_bts",ask_amount_bts)("loan_amount",loan_amount)("price",ask_claim.ask_price)("result",loan_amount*ask_claim.ask_price) );
                         asker_change       = ask_amount_bts - (bid_amount_usd* ask_claim.ask_price);

                         working_bid.amount = 0;
                         working_ask.amount     = asker_change.get_rounded_amount();
                        // working_ask_tmp_amount = asker_change;
                         ask_change             = working_ask;

                         market_trx.inputs.push_back( bid_itr->location );
                         market_trx.outputs.push_back( 
                                 trx_output( claim_by_cover_output( loan_amount, long_claim.pay_address ), collateral_amount) );

                         loan_amount       = asset(static_cast<uint64_t>(0ull),loan_amount.unit);
                         collateral_amount = asset();
                         ++bid_itr;
                         if( bid_itr != bids.rend() ) working_bid = get_output( bid_itr->location );

                         if( working_ask.amount < 10 )
                         {
                            market_trx.inputs.push_back( ask_itr->location );
                            ilog( "ASK CLAIM ADDR ${A} amnt ${a}", ("A",ask_claim.pay_address)("a",pay_asker) );
                            if( pay_asker != asset(static_cast<uint64_t>(0ull),pay_asker.unit) )
                            {
                                market_trx.outputs.push_back( trx_output( claim_by_signature_output( ask_claim.pay_address ), pay_asker) );
                            }
                            pay_asker = asset(pay_asker.unit);
                            ++ask_itr;
                            if( ask_itr != asks.end() )  working_ask = get_output( ask_itr->location );
                         }
                     }
                  }
                  else if( working_bid.claim_func == claim_by_bid )
                  {
                     claim_by_bid_output bid_claim = working_bid.as<claim_by_bid_output>();
                     if( bid_claim.ask_price  < ask_claim.ask_price )
                     {
                        break; // exit the while loop, no more trades can occur
                     }
                     has_change = true;
                     bid_payout_address = bid_claim.pay_address;
                     // fort he purposese of long/long trades assets may be of any type, but
                     // we will assume bids are in usd and asks are in bts for naming convention
                     // purposes.
                     
                     asset bid_amount_usd = working_bid.get_amount();
                     asset bid_amount_bts = bid_amount_usd * bid_claim.ask_price;

                     asset ask_amount_bts = working_ask.get_amount();
                     asset ask_amount_usd = ask_amount_bts * ask_claim.ask_price;
                     ilog( "bid in ${b} expected ${e}", ("b",bid_amount_usd)("e",bid_amount_bts) );
                     ilog( "ask in ${a} expected ${e}", ("a",ask_amount_bts)("e",ask_amount_usd) );

                     if( ask_amount_usd.get_rounded_amount() < bid_amount_usd.get_rounded_amount() )
                     { // then we have filled the ask
                        ilog("ilog ${x} < ${y}???", ("x",ask_amount_usd.amount)("y",bid_amount_usd.amount));
                        pay_asker          += ask_amount_usd;
                        ilog(".");
                        auto delta_bidder  = ask_amount_usd * bid_claim.ask_price;
                        pay_bidder         += delta_bidder; 
                        bidder_change      = bid_amount_usd - delta_bidder * bid_claim.ask_price;

                        ask_change.reset();
                        working_ask.amount = 0;
                        working_bid.amount = bidder_change.get_rounded_amount();
                        bid_change = working_bid;

                        market_trx.inputs.push_back( ask_itr->location );
                        ilog( "ASK CLAIM ADDR ${A} amnt ${a}", ("A",ask_claim.pay_address)("a",pay_asker) );
                        ilog( "BID CHANGE ${C}", ("C", working_bid ) );
                        if( pay_asker > asset(static_cast<uint64_t>(0ull),pay_asker.unit) )
                        {
                          market_trx.outputs.push_back( trx_output( claim_by_signature_output( ask_claim.pay_address ), pay_asker) );
                        }
                        pay_asker = asset(pay_asker.unit);
                        ++ask_itr;
                        if( ask_itr != asks.end() )  working_ask = get_output( ask_itr->location );
                     }
                     else // then we have filled the bid or we have filled BOTH
                     {
                        ilog(".");
                        pay_bidder    += bid_amount_bts;
                        ilog(".");
                        auto delta_asker =  bid_amount_bts * ask_claim.ask_price;
                        pay_asker     += delta_asker;

                        working_bid.amount = 0;

                        if( bid_amount_usd.get_rounded_amount() != ask_amount_usd.get_rounded_amount() )
                        {
                           asker_change  = ask_amount_bts -  delta_asker * ask_claim.ask_price;
                           working_ask.amount = asker_change.get_rounded_amount();
                        }
                        else
                        {
                           working_ask.amount = 0;
                        }

                        market_trx.inputs.push_back( bid_itr->location );
                        ilog( "BID CLAIM ADDR ${A} ${a}", ("A",bid_claim.pay_address)("a",pay_bidder) );
                        market_trx.outputs.push_back( trx_output( claim_by_signature_output( bid_claim.pay_address ), pay_bidder) );
                        pay_bidder = asset(static_cast<uint64_t>(0ull),pay_bidder.unit);

                        ++bid_itr;
                        if( bid_itr != bids.rend() ) working_bid = get_output( bid_itr->location );

                        if( working_ask.amount < 10 )
                        {
                           market_trx.inputs.push_back( ask_itr->location );
                           ilog( "ASK CLAIM ADDR ${A} amnt ${a}", ("A",ask_claim.pay_address)("a",pay_asker) );
                           if( pay_asker.amount > 0 )
                              market_trx.outputs.push_back( trx_output( claim_by_signature_output( ask_claim.pay_address ), pay_asker) );
                           pay_asker = asset(static_cast<uint64_t>(0ull),pay_asker.unit);
                           ++ask_itr;
                           if( ask_itr != asks.end() )  working_ask = get_output( ask_itr->location );
                        }
                     }
                  }
                  else
                  {
                     FC_ASSERT( !"Bid must either be a claim by bid or claim by long",
                                "", ("bid", working_bid) );  
                  }
               } // while( ... ) 
               if( has_change && working_ask.amount > 10  )
               {
                  FC_ASSERT( ask_itr != asks.end() );
                  if( pay_asker.amount > 0 )
                  {
                     market_trx.inputs.push_back( ask_itr->location );
                     market_trx.outputs.push_back( working_ask );
                     market_trx.outputs.push_back( trx_output( claim_by_signature_output( ask_payout_address ), pay_asker ) );
                  }
               }
               if( has_change && working_bid.amount > 10 )
               {
                  FC_ASSERT( bid_itr != bids.rend() );
                  if( collateral_amount.amount > 10 )
                  {
                     market_trx.inputs.push_back( bid_itr->location );
                     market_trx.outputs.push_back( working_bid );
                     market_trx.outputs.push_back( trx_output( claim_by_cover_output( loan_amount, bid_payout_address ), collateral_amount) );
                  }
                  else if( working_bid.claim_func == claim_by_bid )
                  {
                     if( pay_bidder.amount > 10 )
                     {
                        market_trx.inputs.push_back( bid_itr->location );
                        market_trx.outputs.push_back( working_bid );
                        market_trx.outputs.push_back( trx_output( claim_by_signature_output( bid_payout_address ), pay_bidder ) );
                     }
                  }
               }
              
               wlog( "Market Transaction: ${trx}", ("trx", market_trx) );
               if( market_trx.inputs.size() )
               {
                   FC_ASSERT( market_trx.outputs.size() );
                   FC_ASSERT( market_trx.inputs.size() );
                   matched.push_back(market_trx);
               }
               //ilog( "done match orders.." );
            } FC_RETHROW_EXCEPTIONS( warn, "", ("quote",quote)("base",base) ) }
      };
    }

     blockchain_db::blockchain_db()
     :my( new detail::blockchain_db_impl() )
     {
     }

     blockchain_db::~blockchain_db()
     {
     }

     void blockchain_db::open( const fc::path& dir, bool create )
     {
       try {
         if( !fc::exists( dir ) )
         {
              if( !create )
              {
                 FC_THROW_EXCEPTION( file_not_found_exception, 
                     "Unable to open name database ${dir}", ("dir",dir) );
              }
              fc::create_directories( dir );
         }
         my->blk_id2num.open( dir / "blk_id2num", create );
         my->trx_id2num.open( dir / "trx_id2num", create );
         my->meta_trxs.open(  dir / "meta_trxs",  create );
         my->blocks.open(     dir / "blocks",     create );
         my->block_trxs.open( dir / "block_trxs", create );
         my->_market_db.open( dir / "market" );

         
         // read the last block from the DB
         my->blocks.last( my->head_block.block_num, my->head_block );
         if( my->head_block.block_num != uint32_t(-1) )
         {
            my->head_block_id = my->head_block.id();
         }

       } FC_RETHROW_EXCEPTIONS( warn, "error loading blockchain database ${dir}", ("dir",dir)("create",create) );
     }

     void blockchain_db::close()
     {
        my->blk_id2num.close();
        my->trx_id2num.close();
        my->blocks.close();
        my->block_trxs.close();
        my->meta_trxs.close();
     }

    uint32_t blockchain_db::head_block_num()const
    {
       return my->head_block.block_num;
    }
    block_id_type blockchain_db::head_block_id()const
    {
       return my->head_block.id();
    }


    /**
     *  @pre trx must pass evaluate_signed_transaction() without exception
     *  @pre block_num must be a valid block 
     *
     *  @param block_num - the number of the block that contains this trx.
     *
     *  @return the index / trx number that was assigned to trx as part of storing it.
    void  blockchain_db::store_trx( const signed_transaction& trx, const trx_num& trx_idx )
    {
       try {
         my->trx_id2num.store( trx.id(), trx_idx );
         
         meta_trx mt(trx);
         mt.meta_outputs.resize( trx.outputs.size() );
         my->meta_trxs.store( trx_idx, mt );

       } FC_RETHROW_EXCEPTIONS( warn, 
          "an error occured while trying to store the transaction", 
          ("trx",trx) );
    }
     */

    trx_num    blockchain_db::fetch_trx_num( const uint160& trx_id )
    { try {
       return my->trx_id2num.fetch(trx_id);
    } FC_RETHROW_EXCEPTIONS( warn, "trx_id ${trx_id}", ("trx_id",trx_id) ) }

    meta_trx    blockchain_db::fetch_trx( const trx_num& trx_id )
    { try {
       return my->meta_trxs.fetch( trx_id );
    } FC_RETHROW_EXCEPTIONS( warn, "trx_id ${trx_id}", ("trx_id",trx_id) ) }

    uint32_t    blockchain_db::fetch_block_num( const block_id_type& block_id )
    { try {
       return my->blk_id2num.fetch( block_id ); 
    } FC_RETHROW_EXCEPTIONS( warn, "block id: ${block_id}", ("block_id",block_id) ) }

    block_header blockchain_db::fetch_block( uint32_t block_num )
    {
       return my->blocks.fetch(block_num);
    }

    full_block  blockchain_db::fetch_full_block( uint32_t block_num )
    { try {
       full_block fb = my->blocks.fetch(block_num);
       fb.trx_ids = my->block_trxs.fetch( block_num );
       return fb;
    } FC_RETHROW_EXCEPTIONS( warn, "block ${block}", ("block",block_num) ) }

    trx_block  blockchain_db::fetch_trx_block( uint32_t block_num )
    { try {
       trx_block fb = my->blocks.fetch(block_num);
       auto trx_ids = my->block_trxs.fetch( block_num );
       for( uint32_t i = 0; i < trx_ids.size(); ++i )
       {
          auto trx_num = fetch_trx_num(trx_ids[i]);
          fb.trxs.push_back( fetch_trx( trx_num ) );
       }
       // TODO: fetch each trx and add it to the trx block
       //fb.trx_ids = my->block_trxs.fetch( block_num );
       return fb;
    } FC_RETHROW_EXCEPTIONS( warn, "block ${block}", ("block",block_num) ) }

    signed_transaction blockchain_db::fetch_transaction( const transaction_id_type& id )
    { try {
          auto trx_num = fetch_trx_num(id);
          return fetch_trx( trx_num );
    } FC_RETHROW_EXCEPTIONS( warn, "", ("id",id) ) }


    std::vector<meta_trx_input> blockchain_db::fetch_inputs( const std::vector<trx_input>& inputs, uint32_t head )
    {
       try
       {
          if( head == uint32_t(-1) )
          {
            head = head_block_num();
          }

          std::vector<meta_trx_input> rtn;
          rtn.reserve( inputs.size() );
          for( uint32_t i = 0; i < inputs.size(); ++i )
          {
            try {
             trx_num tn   = fetch_trx_num( inputs[i].output_ref.trx_hash );
             meta_trx trx = fetch_trx( tn );
             
             if( inputs[i].output_ref.output_idx >= trx.meta_outputs.size() )
             {
                FC_THROW_EXCEPTION( exception, "Input ${i} references invalid output from transaction ${trx}",
                                    ("i",inputs[i])("trx", trx) );
             }
             if( inputs[i].output_ref.output_idx >= trx.outputs.size() )
             {
                FC_THROW_EXCEPTION( exception, "Input ${i} references invalid output from transaction ${t}",
                                    ("i",inputs[i])("o", trx) );
             }

             meta_trx_input metin;
             metin.source       = tn;
             metin.output_num   = inputs[i].output_ref.output_idx;
             metin.output       = trx.outputs[metin.output_num];
             metin.meta_output  = trx.meta_outputs[metin.output_num];
             rtn.push_back( metin );

            } FC_RETHROW_EXCEPTIONS( warn, "error fetching input [${i}] ${in}", ("i",i)("in", inputs[i]) );
          }
          return rtn;
       } FC_RETHROW_EXCEPTIONS( warn, "error fetching transaction inputs", ("inputs", inputs) );
    }


    /**
     *  Validates that trx could be included in a future block, that
     *  all inputs are unspent, that it is valid for the current time,
     *  and that all inputs have proper signatures and input data.
     *
     *  @return any trx fees that would be paid if this trx were included
     *          in the next block.
     *
     *  @throw exception if trx can not be applied to the current chain state.
     */
    trx_eval blockchain_db::evaluate_signed_transaction( const signed_transaction& trx )       
    {
       try {
           FC_ASSERT( trx.inputs.size() || trx.outputs.size() );
           /** TODO: validate time range on transaction using the previous block time
           if( trx.valid_after != fc::time_point::now() )
           {
             FC_ASSERT( head_block_num() > trx.valid_after.value );
             if( trx.valid_blocks != fc::time_point::now() )
             {
                FC_ASSERT( head_block_num() < trx.valid_after.value + trx.valid_blocks.value );
             }
           }
           */

           trx_validation_state vstate( trx, this ); 
           vstate.validate();

           trx_eval e;
           if( my->head_block_id != block_id_type() )
           {
              // all transactions must pay at least some fee 
              if( vstate.balance_sheet[asset::bts].out >= vstate.balance_sheet[asset::bts].in )
              {
                 // TODO: verify minimum fee
                 FC_ASSERT( vstate.balance_sheet[asset::bts].out <= vstate.balance_sheet[asset::bts].in, 
                            "All transactions must pay some fee",
                 ("out", vstate.balance_sheet[asset::bts].out)("in",vstate.balance_sheet[asset::bts].in )
                            );
              }
              else
              {
                 e.fees = vstate.balance_sheet[asset::bts].in - vstate.balance_sheet[asset::bts].out;
              }
           }
           return e;
       } FC_RETHROW_EXCEPTIONS( warn, "error evaluating transaction ${t}", ("t", trx) );
    }



    trx_eval blockchain_db::evaluate_signed_transactions( const std::vector<signed_transaction>& trxs )
    {
      try {
        trx_eval total_eval;
        for( auto itr = trxs.begin(); itr != trxs.end(); ++itr )
        {
            total_eval += evaluate_signed_transaction( *itr );
        }
        ilog( "summary: ${totals}", ("totals",total_eval) );
        return total_eval;
      } FC_RETHROW_EXCEPTIONS( debug, "" );
    }

    void validate_unique_inputs( const std::vector<signed_transaction>& trxs )
    {
       std::unordered_set<output_reference> ref_outs;
       for( auto itr = trxs.begin(); itr != trxs.end(); ++itr )
       {
          for( auto in = itr->inputs.begin(); in != itr->inputs.end(); ++in )
          {
             if( !ref_outs.insert( in->output_ref ).second )
             {
                FC_THROW_EXCEPTION( exception, "duplicate input detected",
                                            ("in", *in )("trx",*itr)  );
             }
          }
       }
    }
    
    /**
     *  Attempts to append block b to the block chain with the given trxs.
     */
    void blockchain_db::push_block( const trx_block& b )
    {
      try {
        FC_ASSERT( b.version.value                     == fc::unsigned_int(0).value );
        FC_ASSERT( b.trxs.size()                       > 0                          );
        FC_ASSERT( b.block_num                         == head_block_num() + 1      );
        FC_ASSERT( b.prev                              == my->head_block_id         );
        FC_ASSERT( b.trx_mroot                         == b.calculate_merkle_root() );

        //validate_issuance( b, my->head_block /*aka new prev*/ );
        validate_unique_inputs( b.trxs );

        // evaluate all trx and sum the results
        trx_eval total_eval = evaluate_signed_transactions( b.trxs );
        
        wlog( "total_fees: ${tf}", ("tf", total_eval.fees ) );

        my->store( b );
        my->blk_id2num.store( b.id(), b.block_num );
        
      } FC_RETHROW_EXCEPTIONS( warn, "unable to push block", ("b", b) );
    }

    /**
     *  Removes the top block from the stack and marks all spent outputs as 
     *  unspent.
     */
    void blockchain_db::pop_block( full_block& b, std::vector<signed_transaction>& trxs )
    {
       FC_ASSERT( !"TODO: implement pop_block" );
    }


    uint64_t blockchain_db::current_bitshare_supply()
    {
       return my->head_block.total_shares; // cache this every time we push a block
    }

    /**
     *  Generates transactions that match all compatiable bids, asks, and shorts for
     *  all possible asset combinations and returns the result.
     */
    std::vector<signed_transaction> blockchain_db::match_orders()
    { try {
       std::vector<signed_transaction> matched;
       for( uint32_t base = asset::bts; base < asset::count; ++base )
       {
          for( uint32_t quote = base+1; quote < asset::count; ++quote )
          {
              my->match_orders( matched, asset::type(quote), asset::type(base) );
          }
       }
       return matched;
    } FC_RETHROW_EXCEPTIONS( warn, "" ) }

    /**
     *  First step to creating a new block is to take all canidate transactions and 
     *  sort them by fees and filter out transactions that are not valid.  Then
     *  filter out incompatible transactions (those that share the same inputs).
     */
    trx_block  blockchain_db::generate_next_block( const std::vector<signed_transaction>& in_trxs )
    {
      try {
         std::vector<signed_transaction> trxs = match_orders();
         trxs.insert( trxs.end(), in_trxs.begin(), in_trxs.end() );

         std::vector<trx_stat>  stats;
         stats.reserve(trxs.size());
         for( uint32_t i = 0; i < in_trxs.size(); ++i )
         {
            ilog( "trx: ${t} signed by ${s}", ( "t",in_trxs[i])("s",in_trxs[i].get_signed_addresses() ) );
         }
         
         // filter out all trx that generate coins from nothing or don't pay fees
         for( uint32_t i = 0; i < trxs.size(); ++i )
         {
            try 
            {
                trx_stat s;
                s.eval = evaluate_signed_transaction( trxs[i] );

               // TODO: enforce fees
               // if( s.eval.fees.amount == fc::uint128_t(0) )
               // {
               //   wlog( "ignoring transaction ${trx} because it doesn't pay fees\n\n state: ${s}", 
               //         ("trx",trxs[i])("s",s.eval) );
               //   continue;
               // }
                s.trx_idx = i;
                stats.push_back( s );
            } 
            catch ( const fc::exception& e )
            {
               wlog( "unable to use trx ${t}\n ${e}", ("t", trxs[i] )("e",e.to_detail_string()) );
            }
         }

         // order the trx by fees
         std::sort( stats.begin(), stats.end() ); 
         for( uint32_t i = 0; i < stats.size(); ++i )
         {
           ilog( "sort ${i} => ${n}", ("i", i)("n",stats[i]) );
         }


         // calculate the block size as we go
         fc::datastream<size_t>  block_size;
         uint32_t conflicts = 0;

         asset total_fees;

         std::unordered_set<output_reference> consumed_outputs;
         for( size_t i = 0; i < stats.size(); ++i )
         {
            const signed_transaction& trx = trxs[stats[i].trx_idx]; 
            for( size_t in = 0; in < trx.inputs.size(); ++in )
            {
               ilog( "input ${in}", ("in", trx.inputs[in]) );

               if( !consumed_outputs.insert( trx.inputs[in].output_ref ).second )
               {
                    stats[i].trx_idx = uint16_t(-1); // mark it to be skipped, input conflict
                    wlog( "INPUT CONFLICT!" );
                    ++conflicts;
                    break; //in = trx.inputs.size(); // exit inner loop
               }
            }
            if( stats[i].trx_idx != uint16_t(-1) )
            {
               fc::raw::pack( block_size, trx );
               if( block_size.tellp() > MAX_BLOCK_TRXS_SIZE )
               {
                  stats.resize(i); // this trx put us over the top, we can stop processing
                                   // the other trxs.
                  break;
               }
               FC_ASSERT( i < stats.size() );
               ilog( "total fees ${tf} += ${fees}", 
                     ("tf", total_fees)
                     ("fees",stats[i].eval.fees) );
               total_fees += stats[i].eval.fees;
            }
         }

         // at this point we have a list of trxs to include in the block that is sorted by
         // fee and has a set of unique inputs that have all been validated against the
         // current state of the blockchain_db, calculate the total fees paid which are
         // destroyed as the means of paying dividends.
         
       //  wlog( "mining reward: ${mr}", ("mr", calculate_mining_reward( head_block_num() + 1) ) );
        // asset miner_fees( (total_fees.amount).high_bits(), asset::bts );
        // wlog( "miner fees: ${t}", ("t", miner_fees) );

         trx_block new_blk;
         new_blk.trxs.reserve( 1 + stats.size() - conflicts ); 

         // add all other transactions to the block
         for( size_t i = 0; i < stats.size(); ++i )
         {
           if( stats[i].trx_idx != uint16_t(-1) )
           {
             new_blk.trxs.push_back( trxs[ stats[i].trx_idx] );
           }
         }

         new_blk.timestamp                 = fc::time_point::now();
         new_blk.block_num                 = head_block_num() + 1;
         new_blk.prev                      = my->head_block_id;
         new_blk.total_shares              = my->head_block.total_shares - total_fees.amount.high_bits(); 
         new_blk.total_coindays_destroyed  = my->head_block.total_coindays_destroyed; // TODO: Prev Block.CDD + CDD

         new_blk.trx_mroot = new_blk.calculate_merkle_root();

         return new_blk;

      } FC_RETHROW_EXCEPTIONS( warn, "error generating new block" );
    }

    market_data blockchain_db::get_market( asset::type quote, asset::type base )
    {
       market_data d;
       auto bids = my->_market_db.get_bids( quote, base );
       for( auto itr = bids.begin(); itr != bids.end(); ++itr )
       {
           auto working_bid = my->get_output( itr->location );
           if( working_bid.claim_func == claim_by_long )
           {
              claim_by_long_output long_claim = working_bid.as<claim_by_long_output>();
              d.shorts.push_back( short_data( long_claim.ask_price, working_bid.amount  ) );
              d.bids.push_back( bid_data( long_claim.ask_price, 
                                          (asset(working_bid.amount,asset::bts)*long_claim.ask_price ).get_rounded_amount()) );
              d.bids.back().is_short = true;
           }
           else
           {
              claim_by_bid_output bid_claim = working_bid.as<claim_by_bid_output>();
              d.bids.push_back( bid_data( bid_claim.ask_price, working_bid.amount ) );
           }
       }

       auto asks = my->_market_db.get_asks( quote, base );
       for( auto itr = asks.begin(); itr != asks.end(); ++itr )
       {
           auto working_ask = my->get_output( itr->location );
           claim_by_bid_output ask_claim = working_ask.as<claim_by_bid_output>();
           d.asks.push_back( ask_data( ask_claim.ask_price, working_ask.amount ) );
       }
       return d;
    }

    std::string blockchain_db::dump_market( asset::type quote, asset::type base )
    {
      std::stringstream ss;
      ss << "Market "<< fc::variant(quote).as_string() <<" : "<<fc::variant(base).as_string() <<"<br/>\n";
      ss << "Bids<br/>\n";
      auto bids = my->_market_db.get_bids( quote, base );
      for( uint32_t b = 0; b < bids.size(); ++b )
      {
        auto output = my->get_output( bids[b].location );
        ss << b << "] " << fc::json::to_string( output ) <<" <br/>\n";
      }

      ss << "<br/>\nAsks<br/>\n";
      auto asks = my->_market_db.get_asks( quote, base );
      for( uint32_t a = 0; a < asks.size(); ++a )
      {
        auto output = my->get_output( asks[a].location );
        ss << a << "] " << fc::json::to_string( output ) <<" <br/>\n";
      }
      return ss.str();
    }

    uint64_t blockchain_db::get_stake()
    {
       return my->head_block_id._hash[0];
    }
    asset    blockchain_db::get_fee_rate()const
    {
       return asset(static_cast<uint64_t>(1000ull), asset::bts);
    }

}  } // bts::blockchain


