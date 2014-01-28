#pragma once
#include <bts/blockchain/block.hpp>
#include <bts/blockchain/transaction.hpp>

namespace fc 
{
   class path;
};

namespace bts { namespace blockchain {
    #define INVALID_BLOCK_NUM uint32_t(-1)

    namespace detail  { class blockchain_db_impl; }

    /**
     *  Information generated as a result of evaluating a signed
     *  transaction.
     */
    struct trx_eval
    {
       trx_eval():coindays_destroyed(0){}
       asset  fees; // any fees that would be generated
       uint64_t coindays_destroyed;
       trx_eval& operator += ( const trx_eval& e )
       {
         fees               += e.fees;
         coindays_destroyed += e.coindays_destroyed;
         return *this;
       }
    };

    struct trx_num
    {
      /** 
       *  -1 block_num is used to identifiy default initialization.
       */
      static const uint32_t invalid_block_id = INVALID_BLOCK_NUM;
      trx_num(uint32_t b = invalid_block_id, uint16_t t = 0):block_num(b),trx_idx(t){}
      uint32_t block_num;
      uint16_t trx_idx;

      friend bool operator < ( const trx_num& a, const trx_num& b )
      {
        return a.block_num == b.block_num ? 
                    a.trx_idx < b.trx_idx : 
                    a.block_num < b.block_num;
      }
      friend bool operator == ( const trx_num& a, const trx_num& b )
      {
        return a.block_num == b.block_num && a.trx_idx == b.trx_idx;
      }
    };

    /**
     *  Meta information maintained for each output that links it
     *  to the block, trx, and output
     */
    struct meta_trx_output
    {
       meta_trx_output()
       :input_num(-1){}
       trx_num   trx_id;
       uint8_t   input_num;

       bool is_spent()const 
       {
         return trx_id.block_num != trx_num::invalid_block_id;
       }
    };

    /**
     *  Caches output information used by inputs while
     *  evaluating a transaction.
     */
    struct meta_trx_input
    {
       meta_trx_input()
       :output_num(-1){}

       trx_num           source;
       uint8_t           output_num;
       trx_output        output;
       meta_trx_output   meta_output;
    };

    struct meta_trx : public signed_transaction
    {
       meta_trx(){}
       meta_trx( const signed_transaction& t )
       :signed_transaction(t), meta_outputs(t.outputs.size()){}

       std::vector<meta_trx_output> meta_outputs; // tracks where the output was spent
    };

    struct bid_data
    {
       bid_data():amount(0){}
       bid_data( price p, uint64_t a )
       :bid_price(p),amount(a),is_short(false){}

       price    bid_price;
       uint64_t amount;
       bool     is_short;
    };

    struct ask_data
    {
       ask_data():amount(0){}
       ask_data( price p, uint64_t a )
       :ask_price(p),amount(a){}
       price ask_price;
       uint64_t amount;
    };

    struct short_data
    {
       short_data():amount(0){}
       short_data( price p, uint64_t a )
       :short_price(p),amount(a){}

       price short_price;
       uint64_t amount;
    };

    struct margin_data
    {
       price    call_price;
       uint64_t amount;
       uint64_t collateral;
    };

    struct market_data
    {
        std::vector<bid_data>     bids;
        std::vector<ask_data>     asks;
        std::vector<short_data>   shorts;
        std::vector<margin_data>  margins;
    };


    /**
     *  This database only stores valid blocks and applied transactions,
     *  it does not store invalid/orphaned blocks and transactions which
     *  are maintained in a separate database 
     */
    class blockchain_db 
    {
       public:
          blockchain_db();
          ~blockchain_db();

          void open( const fc::path& dir, bool create = true );
          void close();

          uint32_t      head_block_num()const;
          block_id_type head_block_id()const;
          uint64_t      get_stake(); // head - 1 
          asset         get_fee_rate()const;

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
         trx_eval   evaluate_signed_transaction( const signed_transaction& trx );       
         trx_eval   evaluate_signed_transactions( const std::vector<signed_transaction>& trxs );

         std::vector<signed_transaction> match_orders();
         trx_block  generate_next_block( const std::vector<signed_transaction>& trx );

         trx_num    fetch_trx_num( const uint160& trx_id );
         meta_trx   fetch_trx( const trx_num& t );

         signed_transaction          fetch_transaction( const transaction_id_type& trx_id );
         std::vector<meta_trx_input> fetch_inputs( const std::vector<trx_input>& inputs, uint32_t head = INVALID_BLOCK_NUM );

         uint32_t     fetch_block_num( const block_id_type& block_id );
         block_header fetch_block( uint32_t block_num );
         full_block   fetch_full_block( uint32_t block_num );
         trx_block    fetch_trx_block( uint32_t block_num );

         uint64_t   current_bitshare_supply();
         
         /**
          *  Attempts to append block b to the block chain with the given trxs.
          */
         void push_block( const trx_block& b );

         /**
          *  Removes the top block from the stack and marks all spent outputs as 
          *  unspent.
          */
         void pop_block( full_block& b, std::vector<signed_transaction>& trxs );

         std::string dump_market( asset::type quote, asset::type base );

         market_data get_market( asset::type quote, asset::type base );

       private:
         void   store_trx( const signed_transaction& trx, const trx_num& t );
         std::unique_ptr<detail::blockchain_db_impl> my;          
    };

    typedef std::shared_ptr<blockchain_db> blockchain_db_ptr;

}  } // bts::blockchain

FC_REFLECT( bts::blockchain::trx_eval, (fees)(coindays_destroyed) )
FC_REFLECT( bts::blockchain::trx_num, (block_num)(trx_idx) );
FC_REFLECT( bts::blockchain::meta_trx_output, (trx_id)(input_num) )
FC_REFLECT( bts::blockchain::meta_trx_input, (source)(output_num)(output)(meta_output) )
FC_REFLECT_DERIVED( bts::blockchain::meta_trx, (bts::blockchain::signed_transaction), (meta_outputs) );
FC_REFLECT( bts::blockchain::bid_data, (bid_price)(amount)(is_short) )
FC_REFLECT( bts::blockchain::ask_data, (ask_price)(amount) )
FC_REFLECT( bts::blockchain::short_data, (short_price)(amount) )
FC_REFLECT( bts::blockchain::margin_data, (call_price)(amount)(collateral) )
FC_REFLECT( bts::blockchain::market_data, (bids)(asks)(shorts)(margins) )

