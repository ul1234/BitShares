#include <bts/blockchain/blockchain_wallet.hpp>
#include <bts/blockchain/asset.hpp>
#include <bts/blockchain/block.hpp>
#include <bts/extended_address.hpp>
#include <bts/config.hpp>
#include <unordered_map>
#include <map>
#include <fc/filesystem.hpp>
#include <fc/io/raw.hpp>
#include <fc/io/json.hpp>
#include <fc/log/logger.hpp>
#include <fc/reflect/variant.hpp>

#include <iostream>

namespace bts { namespace blockchain {
   struct wallet_data 
   {
       extended_private_key                                 base_key; 
       uint32_t                                             last_used_key;
       uint32_t                                             last_scanned_block_num;
       std::unordered_map<bts::address,std::string>         recv_addresses;
       std::unordered_map<bts::address,std::string>         send_addresses;
       std::vector<fc::ecc::private_key>                    extra_keys;
       std::vector<bts::blockchain::signed_transaction>     transactions;
   };
} } // bts::blockchain

FC_REFLECT( bts::blockchain::wallet_data, 
            (base_key)
            (last_used_key)
            (last_scanned_block_num)
            (recv_addresses)
            (send_addresses)
            (extra_keys)
//            (transactions) // rescan every time we load for now
            )

namespace bts { namespace blockchain {
  
   namespace detail 
   {
      class wallet_impl
      {
          public:
              wallet_impl():_stake(0){}

              fc::path                                                   _wallet_dat;
              wallet_data                                                _data;
              asset                                                      _current_fee_rate;
              uint64_t                                                   _stake;

              std::unordered_map<output_reference,trx_output>            _unspent_outputs;
              std::unordered_map<output_reference,trx_output>            _spent_outputs;

              // maps address to private key index
              std::unordered_map<bts::address,uint32_t>                  _my_addresses;
              std::unordered_map<transaction_id_type,signed_transaction> _id_to_signed_transaction;

              asset get_balance( asset::type balance_type )
              {
                   asset total_bal( static_cast<uint64_t>(0ull), balance_type);
                   std::vector<trx_input> inputs;
                   for( auto itr = _unspent_outputs.begin(); itr != _unspent_outputs.end(); ++itr )
                   {
                      //ilog( "unspent outputs ${o}", ("o",*itr) );
                       if( itr->second.claim_func == claim_by_signature && itr->second.unit == balance_type )
                       {
                           total_bal += itr->second.get_amount(); // TODO: apply interest earned 
                       }
                   }
                   return total_bal;
              }


              /**
               *  Collect inputs that total to at least min_amnt.
               */
              std::vector<trx_input> collect_inputs( const asset& min_amnt, asset& total_in, std::unordered_set<bts::address>& req_sigs )
              {
                   std::vector<trx_input> inputs;
                   for( auto itr = _unspent_outputs.begin(); itr != _unspent_outputs.end(); ++itr )
                   {
                      ilog( "unspent outputs ${o}", ("o",*itr) );
                       if( itr->second.claim_func == claim_by_signature && itr->second.unit == min_amnt.unit )
                       {
                           inputs.push_back( trx_input( itr->first ) );
                           total_in += itr->second.get_amount();
                           req_sigs.insert( itr->second.as<claim_by_signature_output>().owner );
                           ilog( "total in ${in}  min ${min}", ( "in",total_in)("min",min_amnt) );
                           if( total_in >= min_amnt )
                           {
                              return inputs;
                           }
                       }
                   }
                   FC_ASSERT( !"Unable to collect sufficient unspent inputs", "", ("min_amnt",min_amnt)("total_collected",total_in) );
              }

              asset get_margin_balance( asset::type unit, asset& total_collat )
              {
                   asset total_due( static_cast<uint64_t>(0ull), unit );
                   std::multimap<price,trx_input> inputs;
                   for( auto itr = _unspent_outputs.begin(); itr != _unspent_outputs.end(); ++itr )
                   {
                       if( itr->second.claim_func == claim_by_cover )
                       {
                           auto cbc = itr->second.as<claim_by_cover_output>();
                           if( cbc.payoff_unit == unit )
                           {
                              asset payoff( cbc.payoff_amount, unit );
                              total_due += payoff;
                              total_collat += itr->second.get_amount();
                           }
                       }
                   }
                   return total_due;
              }

              /**
               *  Collect claim_by_cover inputs that total to at least min_amnt.
               */
              std::vector<trx_input> collect_cover_inputs( const asset& min_amnt, 
                                                           asset& total_collat, 
                                                           asset& total_payoff, 
                                                           std::unordered_set<bts::address>& req_sigs )
              {
                   std::multimap<price,trx_input> inputs;
                   for( auto itr = _unspent_outputs.begin(); itr != _unspent_outputs.end(); ++itr )
                   {
                       if( itr->second.claim_func == claim_by_cover )
                       {
                           auto cbc = itr->second.as<claim_by_cover_output>();
                           if( cbc.payoff_unit == min_amnt.unit )
                           {
                              asset payoff( cbc.payoff_amount, min_amnt.unit );
                              inputs.insert( std::pair<price,trx_input>( payoff / itr->second.get_amount(), trx_input( itr->first )  ) );

                           }
                       }
                   }

                   std::vector<trx_input> results;
                   for( auto ritr = inputs.rbegin(); ritr != inputs.rend(); ++ritr )
                   {
                       auto out = get_cover_output( ritr->second.output_ref ); 
                       auto cover_out = out.as<claim_by_cover_output>();
                       asset payoff( cover_out.payoff_amount, cover_out.payoff_unit );

                       total_payoff += payoff;
                       total_collat += out.get_amount();
                       req_sigs.insert( cover_out.owner );
                       results.push_back( ritr->second );

                       if( (asset() != min_amnt) && total_payoff >= min_amnt )
                       {
                          return results;
                       }
                   }
                   FC_ASSERT( !"Unable to collect sufficient unspent inputs", "", ("min_amnt",min_amnt) );
              }

              trx_output get_cover_output( const output_reference& r )
              { try {
                  auto itr = _unspent_outputs.find(r);
                  FC_ASSERT( itr != _unspent_outputs.end() );
                  FC_ASSERT( itr->second.claim_func = claim_by_cover );
                  return itr->second;
              } FC_RETHROW_EXCEPTIONS( warn, "unable to find ${r}", ("r",r) ) }


              /** completes a transaction signing it and logging it, this is different than wallet::sign_transaction which
               *  merely signs the transaction without checking anything else or storing the transaction.
               **/
              void sign_transaction( signed_transaction& trx, const std::unordered_set<address>& addresses )
              {
                   trx.stake = _stake;
                   trx.timestamp = fc::time_point::now();
                   for( auto itr = addresses.begin(); itr != addresses.end(); ++itr )
                   {
                      self->sign_transaction( trx, *itr );
                   }
                   for( auto itr = trx.inputs.begin(); itr != trx.inputs.end(); ++itr )
                   {
                       elog( "MARK AS SPENT ${B}", ("B",itr->output_ref) );
                       self->mark_as_spent( itr->output_ref );
                   }
                   _data.transactions.push_back(trx);
              }
              wallet* self;
      };
   } // namespace detail

   wallet::wallet()
   :my( new detail::wallet_impl() )
   {
      my->self = this;
   }

   wallet::~wallet()
   {
      save();
   }

   void wallet::open( const fc::path& wallet_dat )
   { try {
      my->_wallet_dat = wallet_dat;
      if( fc::exists( wallet_dat ) )
      {
         my->_data = fc::json::from_file<bts::blockchain::wallet_data>( wallet_dat );
      }
      else
      {
         my->_data.base_key = extended_private_key( fc::ecc::private_key::generate().get_secret(), 
                                                    fc::ecc::private_key::generate().get_secret() );
         save();
      }
      for( uint32_t i = 0; i < my->_data.extra_keys.size(); ++i )
      {
         my->_my_addresses[bts::address(my->_data.extra_keys[i].get_public_key())] = i;
      }
   } FC_RETHROW_EXCEPTIONS( warn, "unable to load ${wal}", ("wal",wallet_dat) ) }

   void wallet::save()
   {
      ilog( "saving wallet\n" );
      fc::json::save_to_file( my->_data, my->_wallet_dat );
   }

   asset wallet::get_balance( asset::type t )
   {
      return my->get_balance(t);
   }
   asset wallet::get_margin( asset::type t, asset& collat )
   {
      return my->get_margin_balance( t, collat );
   }

   void           wallet::set_stake( uint64_t stake )
   {
      wlog( "STAKE ${S}", ("S",stake) );
      my->_stake = stake;
   }

   void           wallet::import_key( const fc::ecc::private_key& key )
   {
      my->_data.extra_keys.push_back(key);
      my->_my_addresses[ key.get_public_key() ] = my->_data.extra_keys.size() -1;
   }

   bts::address   wallet::get_new_address()
   {
      my->_data.last_used_key++;
      auto new_key = my->_data.base_key.child( my->_data.last_used_key );
      import_key(new_key);
      //bts::address addr = new_key.get_public_key();
      return  new_key.get_public_key();
   }

   std::vector<bts::address>   wallet::list_address()
   {
	   std::vector<bts::address> address;
	   
	   for(auto itr=my->_my_addresses.begin();itr!=my->_my_addresses.end();++itr)
	   {
		   address.push_back(itr->first);
	   }

	   return address;
   }

   void                  wallet::set_fee_rate( const asset& pts_per_byte )
   {
      my->_current_fee_rate = pts_per_byte;
   }

   signed_transaction    wallet::transfer( const asset& amnt, const bts::address& to )
   { try {
       auto   change_address = get_new_address();

       std::unordered_set<bts::address> req_sigs; 
       asset  total_in(static_cast<uint64_t>(0ull),amnt.unit);

       signed_transaction trx; 
       trx.inputs    = my->collect_inputs( amnt, total_in, req_sigs );

       asset change = total_in - amnt;

       trx.outputs.push_back( trx_output( claim_by_signature_output( to ), amnt) );
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change) );

       trx.sigs.clear();
       my->sign_transaction( trx, req_sigs );

       uint64_t trx_bytes = fc::raw::pack( trx ).size();
       asset    fee( my->_current_fee_rate * trx_bytes );

       if( amnt.unit == asset::bts )
       {
          if( total_in >= amnt + fee )
          {
              change = change - fee;
              trx.outputs.back() = trx_output( claim_by_signature_output( change_address ), change );
              if( change == asset() ) trx.outputs.pop_back(); // no change required
          }
          else
          {
              elog( "NOT ENOUGH TO COVER AMOUNT + FEE... GRAB MORE.." );
              // TODO: this function should be recursive here, but having 2x the fee should be good enough
              fee = fee + fee; // double the fee in this case to cover the growth
              req_sigs.clear();
              total_in = asset();
              trx.inputs = my->collect_inputs( amnt+fee, total_in, req_sigs );
              change =  total_in - amnt - fee;
              trx.outputs.back() = trx_output( claim_by_signature_output( change_address ), change );
              if( change == asset() ) trx.outputs.pop_back(); // no change required
          }
       }
       else /// fee is in bts, but we are transferring something else
       {
           if( change.amount == fc::uint128_t(0) ) trx.outputs.pop_back(); // no change required

           // TODO: this function should be recursive here, but having 2x the fee should be good enough, some
           // transactions may overpay in this case, but this can be optimized later to reduce fees.. for now
           fee = fee + fee; // double the fee in this case to cover the growth
           asset total_fee_in;
           auto extra_in = my->collect_inputs( fee, total_fee_in, req_sigs );
           trx.inputs.insert( trx.inputs.end(), extra_in.begin(), extra_in.end() );
           trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), total_fee_in - fee ) );
       }

       trx.sigs.clear();
       my->sign_transaction(trx, req_sigs);
       
       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "${amnt} to ${to}", ("amnt",amnt)("to",to) ) }

   void wallet::mark_as_spent( const output_reference& r )
   {
     // wlog( "MARK SPENT ${s}", ("s",r) );
      auto itr = my->_unspent_outputs.find(r);
      if( itr == my->_unspent_outputs.end() )
      {
          return;
      }
      my->_unspent_outputs.erase(r);
      my->_spent_outputs[r] = itr->second;
   }

   void wallet::sign_transaction( signed_transaction& trx, const bts::address& addr )
   {
      ilog( "Sign ${trx}  ${addr}", ("trx",trx.id())("addr",addr));
      auto priv_key_idx = my->_my_addresses.find(addr);
      FC_ASSERT( priv_key_idx != my->_my_addresses.end() );
      trx.sign( my->_data.extra_keys[priv_key_idx->second] );
   }

   /** When bidding on an asset you specify the asset you have and the price you would like
    * to sell it at.
    */
   signed_transaction    wallet::bid( const asset& amnt, const price& ratio )
   { try {
       auto   change_address = get_new_address();

       signed_transaction trx; 
       std::unordered_set<bts::address> req_sigs; 
       asset  total_in(static_cast<uint64_t>(0ull),amnt.unit);

       asset amnt_with_fee = amnt; // TODO: add fee of .1% 

       trx.inputs    = my->collect_inputs( amnt_with_fee, total_in, req_sigs );
       asset change  = total_in - amnt;
       ilog( "change ${c}", ("c",change) );

       trx.outputs.push_back( trx_output( claim_by_bid_output( change_address, ratio ), amnt) );
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change) );

       trx.sigs.clear();
       my->sign_transaction( trx, req_sigs );

       uint32_t trx_bytes = fc::raw::pack( trx ).size();
       asset    fee( my->_current_fee_rate * trx_bytes );

       if( amnt.unit == asset::bts )
       {
            if( total_in >= amnt + fee )
            {
                change = change - fee;
                ilog( "change - fee = ${c}, fee: ${f}", ("c",change)("f",fee) );
                trx.outputs.back() = trx_output( claim_by_signature_output( change_address ), change );
                if( change == asset() ) trx.outputs.pop_back(); // no change required
            }
            else
            {
              elog( "NOT ENOUGH TO COVER AMOUNT + FEE... GRAB MORE.." );
              fee = fee + fee; // double the fee in this case to cover the growth
              req_sigs.clear();
              total_in = asset();
              trx.inputs = my->collect_inputs( amnt+fee, total_in, req_sigs );
              change =  total_in - amnt - fee;
              ilog( "total_in - amnt - fee = ${c}, fee: ${f} total_in: ${i}", ("c",change)("f",fee)("i",total_in) );
              trx.outputs.back() = trx_output( claim_by_signature_output( change_address ), change );
              if( change == asset() ) trx.outputs.pop_back(); // no change required
            }
       }
       else
       {
           if( change.amount == fc::uint128_t(0) ) trx.outputs.pop_back(); // no change required

           // TODO: this function should be recursive here, but having 2x the fee should be good enough, some
           // transactions may overpay in this case, but this can be optimized later to reduce fees.. for now
           fee = fee + fee; // double the fee in this case to cover the growth
           asset total_fee_in;
           auto extra_in = my->collect_inputs( fee, total_fee_in, req_sigs );
           trx.inputs.insert( trx.inputs.end(), extra_in.begin(), extra_in.end() );
           trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), total_fee_in - fee ) );
       }

       trx.sigs.clear();
       my->sign_transaction( trx, req_sigs );

       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "${amnt} @ ${price}", ("amnt",amnt)("price",ratio) ) }

   signed_transaction    wallet::short_sell( const asset& borrow_amnt, const price& ratio )
   { try {
       auto   amnt = borrow_amnt * ratio;
       FC_ASSERT( borrow_amnt.unit != asset::bts, "You cannot short sell BTS" );
       auto   change_address = get_new_address();

       auto bts_in = amnt;

       signed_transaction trx; 
       std::unordered_set<bts::address> req_sigs; 
       asset  total_in;

       asset in_with_fee = bts_in; // TODO: add fee proportional to trx size...

       trx.inputs    = my->collect_inputs( in_with_fee, total_in, req_sigs );
       asset change  = total_in - bts_in;

       trx.outputs.push_back( trx_output( claim_by_long_output( change_address, ratio ), amnt) );
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change) );

       trx.sigs.clear();
       my->sign_transaction( trx, req_sigs );

       uint32_t trx_bytes = fc::raw::pack( trx ).size();
       asset    fee( my->_current_fee_rate * trx_bytes );

       if( total_in >= amnt + fee )
       {
           change = change - fee;
           trx.outputs.back() = trx_output( claim_by_signature_output( change_address ), change );
           if( change == asset() ) trx.outputs.pop_back(); // no change required
       }
       else
       {
           elog( "NOT ENOUGH TO COVER AMOUNT + FEE... GRAB MORE.." );
           // TODO: this function should be recursive here, but having 2x the fee should be good enough
           fee = fee + fee; // double the fee in this case to cover the growth
           req_sigs.clear();
           total_in = asset();
           trx.inputs = my->collect_inputs( amnt+fee, total_in, req_sigs );
           change =  total_in - amnt - fee;
           trx.outputs.back() = trx_output( claim_by_signature_output( change_address ), change );
           if( change == asset() ) trx.outputs.pop_back(); // no change required
       }

       trx.sigs.clear();
       my->sign_transaction(trx, req_sigs);

       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "${amnt} @ ${price}", ("amnt",borrow_amnt)("price",ratio) ) }

   signed_transaction    wallet::cancel_bid( const output_reference& bid )
   { try {
       signed_transaction trx; 
       std::unordered_set<bts::address> req_sigs; 
       auto bid_out_itr = my->_unspent_outputs.find(bid);
       FC_ASSERT( bid_out_itr != my->_unspent_outputs.end() );

       trx.inputs.push_back( trx_input( bid ) );
       if( bid_out_itr->second.claim_func == claim_by_bid )
       {
          auto bid_out = bid_out_itr->second.as<claim_by_bid_output>();
          trx.outputs.push_back( trx_output( claim_by_signature_output( bid_out.pay_address ), 
                                             bid_out_itr->second.amount, bid_out_itr->second.unit ) );
          req_sigs.insert( bid_out.pay_address);
       }
       else if( bid_out_itr->second.claim_func == claim_by_long )
       {
          auto bid_out = bid_out_itr->second.as<claim_by_long_output>();
          trx.outputs.push_back( trx_output( claim_by_signature_output( bid_out.pay_address ), 
                                             bid_out_itr->second.amount, bid_out_itr->second.unit ) );
          req_sigs.insert( bid_out.pay_address);
       }
       // TODO: collect fee for this transaction
       

       my->sign_transaction( trx, req_sigs );

       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "unable to find bid", ("bid",bid) ) }



   /**
    *  Builds a transaction to cover amnt of short positions starting with the highest price
    *  first and working down.
    */
   signed_transaction    wallet::cover( const asset& amnt )
   { try {
       wlog( "Cover ${amnt}", ("amnt",amnt) );
       auto   change_address = get_new_address();
       signed_transaction trx; 
       std::unordered_set<bts::address> req_sigs; 
       asset  total_in(static_cast<uint64_t>(0ull),amnt.unit);
       asset  cover_in(static_cast<uint64_t>(0ull),amnt.unit);
       asset  collat_in(static_cast<uint64_t>(0ull),asset::bts);

       trx.inputs         = my->collect_inputs( amnt, total_in, req_sigs );
       asset change = total_in - amnt;

       asset freed_collateral;
       // return a vector of inputs sorted from highest price to lowest price, user should
       // always cover the highest price positions first.
       auto cover_inputs  = my->collect_cover_inputs( amnt, collat_in, cover_in, req_sigs );
       auto remaining = amnt;
       for( auto itr = cover_inputs.begin(); itr != cover_inputs.end(); ++itr )
       {
          trx.inputs.push_back( *itr );

          auto txout = my->get_cover_output( itr->output_ref );
          auto cover_out = txout.as<claim_by_cover_output>();

          asset payoff( cover_out.payoff_amount, cover_out.payoff_unit );

          wlog( "Payoff ${amnt}  Collateral ${c}", ("amnt",amnt)("c",txout.get_amount()) );

          // if remaining > itr->owed then free 100% of the collateral and remaining -= itr->owed
          if( remaining >= payoff )
          {
             freed_collateral += txout.get_amount();
             remaining -= payoff;
          }

          // if remaining is < itr->owed then free remaining and create a new cover output with the balance
          //  proportional to the amount paid off.
          else if( remaining < payoff )
          {
              auto price               = collat_in / cover_in; //txout.get_amount() / payoff;
              wlog( "In Price ${price}", ("price",price) );

              auto leftover_collateral   = (payoff - remaining) * price;
              auto leftover_debt         = leftover_collateral  * price;
              wlog( "Leftover Collateral ${price}", ("price",price) );
              wlog( "Leftover Debt  ${price}", ("price",price) );

              freed_collateral += txout.get_amount() - leftover_collateral; //remaining * price;
             // freed_collateral.amount *= 9; // -= asset(COIN / 1000,asset::bts); // TODO: this is a hack to fix rounding errors

              if( leftover_debt.amount.high_bits() > 2 )
              {
                 freed_collateral.amount *= 3; // -= asset(COIN / 1000,asset::bts); // TODO: this is a hack to fix rounding errors
                 freed_collateral.amount /= 4; // -= asset(COIN / 1000,asset::bts); // TODO: this is a hack to fix rounding errors
                 trx.outputs.push_back( trx_output( claim_by_cover_output( leftover_debt, cover_out.owner ), collat_in - freed_collateral ) );
              }
              break;
          }
       }
       // if remaining > 0 then change += remaining.

       const fc::uint128_t zero(0);

       if( freed_collateral.amount != zero )
          trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), freed_collateral ) );
       if( change.amount != zero )
          trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change) );

       // TODO: calculate fees... apply them... 

       ilog( "req sigs ${sigs}", ("sigs",req_sigs) );
       my->sign_transaction( trx, req_sigs );
       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "${asset}", ("asset",amnt) ) }

   signed_transaction wallet::add_margin( const asset& collateral_amount, asset::type u )
   { try {
       FC_ASSERT( collateral_amount.unit == asset::bts );
       FC_ASSERT( u != asset::bts );

       auto   change_address = get_new_address();

       signed_transaction trx;
       std::unordered_set<bts::address> req_sigs; 
       asset  total_in(static_cast<uint64_t>(0ull),u);
       asset  cover_in(static_cast<uint64_t>(0ull),u);
       asset  collat_in(static_cast<uint64_t>(0ull),asset::bts);

       trx.inputs         = my->collect_inputs( collateral_amount, total_in, req_sigs );
       asset change = total_in - collateral_amount;

       auto cover_inputs  = my->collect_cover_inputs( asset(), collat_in, cover_in, req_sigs );
       trx.inputs.insert( trx.inputs.end(), cover_inputs.begin(), cover_inputs.end() );

       trx.outputs.push_back( trx_output( claim_by_cover_output( cover_in, change_address ), collat_in + collateral_amount ) );
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change ) );

       // TODO: apply fees 

       my->sign_transaction( trx, req_sigs );
       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "additional collateral: ${c} for ${u}", ("c",collateral_amount)("u",u) ) }

   // all outputs are claim_by_bid
   std::unordered_map<output_reference,trx_output> wallet::get_open_bids()
   {
      std::unordered_map<output_reference,trx_output> bids;
      return bids;
   }

   // all outputs are claim_by_long
   std::unordered_map<output_reference,trx_output> wallet::get_open_short_sell()
   {
      std::unordered_map<output_reference,trx_output> bids;
      return bids;
   }

   // all outputs are claim_by_cover,
   std::unordered_map<output_reference,trx_output> wallet::get_open_shorts()
   {
      std::unordered_map<output_reference,trx_output> bids;
      return bids;
   }


   std::unordered_map<output_reference,trx_output> wallet::get_closed_bids()
   {
      std::unordered_map<output_reference,trx_output> bids;
      return bids;
   }

   std::unordered_map<output_reference,trx_output> wallet::get_closed_short_sell()
   {
      std::unordered_map<output_reference,trx_output> bids;
      return bids;
   }

   std::unordered_map<output_reference,trx_output> wallet::get_covered_shorts()
   {
      std::unordered_map<output_reference,trx_output> bids;
      return bids;
   }



   /** returns all transactions issued */
   std::vector<signed_transaction> wallet::get_transaction_history()
   {
      return my->_data.transactions;
   }

   /**
    *  Scan the blockchain starting from_block_num until the head block, check every
    *  transaction for inputs or outputs accessable by this wallet.
    *
    *  @return true if a new input was found or output spent
    */
   bool wallet::scan_chain( blockchain_db& chain, uint32_t from_block_num )
   { try {
       bool found = false;
       auto head_block_num = chain.head_block_num();
       // for each block
       for( uint32_t i = from_block_num; i <= head_block_num; ++i )
       {
          ilog( "block: ${i}", ("i",i ) );
          auto blk = chain.fetch_full_block( i );
          // for each transaction
          for( uint32_t trx_idx = 0; trx_idx < blk.trx_ids.size(); ++trx_idx )
          {
              ilog( "trx: ${trx_idx}", ("trx_idx",trx_idx ) );
              auto trx = chain.fetch_trx( trx_num( i, trx_idx ) ); //blk.trx_ids[trx_idx] );
              ilog( "${id} \n\n  ${trx}\n\n", ("id",trx.id())("trx",trx) );

              for( uint32_t in_idx = 0; in_idx < trx.inputs.size(); ++in_idx )
              {
                  mark_as_spent( trx.inputs[in_idx].output_ref );
              }

              // for each output
              for( uint32_t out_idx = 0; out_idx < trx.outputs.size(); ++out_idx )
              {
                  const trx_output& out = trx.outputs[out_idx];
                  auto out_ref          = output_reference( trx.id(),out_idx );
                  switch( out.claim_func )
                  {
                     case claim_by_signature:
                     {
                        auto owner = out.as<claim_by_signature_output>().owner;
                        auto aitr  = my->_my_addresses.find(owner);
                        if( aitr != my->_my_addresses.end() )
                        {
                            if( !trx.meta_outputs[out_idx].is_spent() )
                               my->_unspent_outputs[output_reference( trx.id(), out_idx )] = trx.outputs[out_idx];
                            else
                            {
                               mark_as_spent( out_ref ); //output_reference(trx.id(), out_idx ) );
                               //my->_spent_outputs[output_reference( trx.id(), out_idx )] = trx.outputs[out_idx];
                            }
                           // std::cerr<<"found block["<<i<<"].trx["<<trx_idx<<"].output["<<out_idx<<"]  " << std::string(trx.id()) <<" => "<<std::string(owner)<<"\n";
                           found = true;
                        }
                        else
                        {
                            // std::cerr<<"skip block["<<i<<"].trx["<<trx_idx<<"].output["<<out_idx<<"] => "<<std::string(owner)<<"\n";
                        }
                        break;
                     }
                     case claim_by_bid:
                     {
                        auto bid = out.as<claim_by_bid_output>();
                        auto aitr = my->_my_addresses.find(bid.pay_address);
                        if( aitr != my->_my_addresses.end() )
                        {
                            found = true;
                            if( trx.meta_outputs[out_idx].is_spent() )
                            {
                               mark_as_spent( out_ref );
                               //my->_unspent_outputs.erase(out_ref);
                              // my->_spent_outputs[out_ref] = trx.outputs[out_idx];
                            }
                            else
                            {
                               my->_unspent_outputs[out_ref] = trx.outputs[out_idx];
                            }
                        }
                        else
                        {
                           // skip, it doesn't belong to me
                        }
                        break;
                     }
                     case claim_by_long:
                     {
                        auto short_sell = out.as<claim_by_long_output>();
                        auto aitr = my->_my_addresses.find(short_sell.pay_address);
                        if( aitr != my->_my_addresses.end() )
                        {
                            found = true;
                            if( trx.meta_outputs[out_idx].is_spent() )
                            {
                               mark_as_spent( out_ref );
                             //  my->_unspent_outputs.erase(out_ref);
                             //  my->_spent_outputs[out_ref] = trx.outputs[out_idx];
                            }
                            else
                            {
                               my->_unspent_outputs[out_ref] = trx.outputs[out_idx];
                            }
                        }
                        else
                        {
                           // skip, it doesn't belong to me
                        }
                        break;
                     }
                     case claim_by_cover:
                     {
                        auto cover = out.as<claim_by_cover_output>();
                        auto aitr = my->_my_addresses.find(cover.owner);
                        if( aitr != my->_my_addresses.end() )
                        {
                            found = true;
                            if( trx.meta_outputs[out_idx].is_spent() )
                            {
                               mark_as_spent( out_ref );
                               //my->_unspent_outputs.erase(out_ref);
                               //my->_spent_outputs[out_ref] = trx.outputs[out_idx];
                            }
                            else
                            {
                               elog( "UNSPENT COVER DISCOVERED ${B}", ("B",out_ref) );
                               my->_unspent_outputs[out_ref] = trx.outputs[out_idx];
                            }
                        }
                        else
                        {
                           // skip, it doesn't belong to me
                        }
                        break;
                     }
                  }
              }
          }
       }
       return found;
   } FC_RETHROW_EXCEPTIONS( warn, "" ) }

   void wallet::dump()
   {
       std::cerr<<"===========================================================\n";
       std::cerr<<"Unspent Outputs: \n";
       for( auto itr = my->_unspent_outputs.begin(); itr != my->_unspent_outputs.end(); ++itr )
       {
           switch( itr->second.claim_func )
           {
              case claim_by_signature:
                 std::cerr<<std::string(itr->first.trx_hash)<<":"<<int(itr->first.output_idx)<<"]  ";
                 std::cerr<<std::string(itr->second.get_amount())<<" ";
                 std::cerr<<fc::variant(itr->second.claim_func).as_string()<<" ";
                 std::cerr<< std::string(itr->second.as<claim_by_signature_output>().owner);
                 std::cerr<<"\n";
                 break;
           }
       }
       std::cerr<<"\n";
       std::cerr<<"Open Bids: \n";
     //  auto open_bids = get_open_bids();
     //  for( auto itr = open_bids.begin(); itr != open_bids.end(); ++itr )
       for( auto itr = my->_unspent_outputs.begin(); itr != my->_unspent_outputs.end(); ++itr )
       {

           switch( itr->second.claim_func )
           {
              case claim_by_bid:
                 std::cerr<<std::string(itr->first.trx_hash)<<":"<<int(itr->first.output_idx)<<"]  ";
                 std::cerr<<std::string(itr->second.get_amount())<<" ";
                 std::cerr<<fc::variant(itr->second.claim_func).as_string()<<" ";

                 std::cerr<< std::string(itr->second.as<claim_by_bid_output>().ask_price);
                 std::cerr<< " owner: ";
                 std::cerr<< std::string(itr->second.as<claim_by_bid_output>().pay_address);
                 std::cerr<< " min trade: "<< itr->second.as<claim_by_bid_output>().min_trade;
                 std::cerr<<"\n";
                 break;
              default:
                 break;
           }
       }
       std::cerr<<"\nOpen Short Sells: \n";
       //auto open_short_sells = get_open_short_sell();
       for( auto itr = my->_unspent_outputs.begin(); itr != my->_unspent_outputs.end(); ++itr )
      // for( auto itr = open_short_sells.begin(); itr != open_short_sells.end(); ++itr )
       {

           switch( itr->second.claim_func )
           {
              case claim_by_long:
                 std::cerr<<std::string(itr->first.trx_hash)<<":"<<int(itr->first.output_idx)<<"]  ";
                 std::cerr<<std::string(itr->second.get_amount())<<" ";
                 std::cerr<<fc::variant(itr->second.claim_func).as_string()<<" ";
                 std::cerr<< std::string(itr->second.as<claim_by_long_output>().ask_price);
                 std::cerr<< " owner: ";
                 std::cerr<< std::string(itr->second.as<claim_by_long_output>().pay_address);
                 std::cerr<< " min trade: "<< itr->second.as<claim_by_long_output>().min_trade;
                 std::cerr<<"\n";
                 break;
              default:
                 break;
        //         std::cerr<<"??";
           }
       }

       std::cerr<<"\nOpen Margin Positions: \n";
       //auto open_shorts = get_open_shorts();
       //for( auto itr = open_shorts.begin(); itr != open_shorts.end(); ++itr )
       for( auto itr = my->_unspent_outputs.begin(); itr != my->_unspent_outputs.end(); ++itr )
       {

           switch( itr->second.claim_func )
           {
              case claim_by_cover:
              {
                 std::cerr<<std::string(itr->first.trx_hash)<<":"<<int(itr->first.output_idx)<<"]  ";
                 std::cerr<<std::string(itr->second.get_amount())<<" ";
                 std::cerr<<fc::variant(itr->second.claim_func).as_string()<<" ";

                 auto cover = itr->second.as<claim_by_cover_output>();
                 auto payoff = asset(cover.payoff_amount,cover.payoff_unit);
                 auto payoff_threshold = asset(uint64_t(cover.payoff_amount*double(1.5)*COIN),cover.payoff_unit);
                 std::cerr<< std::string(payoff);
                 std::cerr<< " owner: ";
                 std::cerr<< std::string(itr->second.as<claim_by_cover_output>().owner);
                 // this is the break even price... we actually need to cover at half the price?
                 std::cerr<< " price: " << std::string(payoff_threshold / itr->second.get_amount());
                 std::cerr<<"\n";
                 break;
              }
              default:
                  break;
           }
       }
       std::cerr<<"===========================================================\n";
   }

    
} } // namespace bts::blockchain
