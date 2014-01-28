#pragma once
#include <bts/blockchain/blockchain_db.hpp>
#include <unordered_map>

namespace bts { namespace blockchain {

   namespace detail { class wallet_impl; }

   /**
    *  The wallet stores all signed_transactions that reference one of its
    *  addresses in the inputs or outputs section.  It also tracks all
    *  private keys, spend states, etc...
    */
   class wallet
   {
        public:
           wallet();
           ~wallet();

           void open( const fc::path& wallet_file );
           void save();

           bts::address          get_new_address();
		   std::vector<bts::address> list_address();
           asset                 get_balance( asset::type t );
           asset                 get_margin( asset::type t, asset& collat );
           void                  set_stake( uint64_t stake );
           void                  import_key( const fc::ecc::private_key& key );
           void                  set_fee_rate( const asset& pts_per_byte );
           uint64_t              last_scanned()const;

           signed_transaction    transfer( const asset& amnt, const bts::address& to );
           signed_transaction    bid( const asset& amnt, const price& ratio );
           signed_transaction    short_sell( const asset& amnt, const price& ratio );
           signed_transaction    cancel_bid( const output_reference& bid );
           signed_transaction    cancel_short_sell( const output_reference& bid );

           /** returns all transactions issued */
           std::vector<signed_transaction> get_transaction_history();

           // automatically covers position with lowest margin which is the position entered 
           // at the lowest price...
           signed_transaction    cover( const asset& amnt );
           /**
            * Combines all margin positions into a new position with additional collateral. In the
            * future smarter wallets may want to only apply this to a subset of the positions.
            *
            * @param u - the asset class to increase margin for (anything but BTS)
            * @param amnt - the amount of additional collateral (must be BTS)
            */
           signed_transaction    add_margin( const asset& collateral_amount /*bts*/, asset::type u );

           // all outputs are claim_by_bid
           std::unordered_map<output_reference,trx_output> get_open_bids();

           // all outputs are claim_by_long
           std::unordered_map<output_reference,trx_output> get_open_short_sell();

           // all outputs are claim_by_cover,
           std::unordered_map<output_reference,trx_output> get_open_shorts();

           // all outputs are claim_by_bid, these bids were either canceled or executed
           std::unordered_map<output_reference,trx_output> get_closed_bids();

           // all outputs are claim_by_long, these bids were either canceled or executed
           std::unordered_map<output_reference,trx_output> get_closed_short_sell();

           // all outputs are claim_by_cover, these short positions have been covered
           std::unordered_map<output_reference,trx_output> get_covered_shorts();

           void sign_transaction( signed_transaction& trx, const bts::address& addr );
           bool scan_chain( blockchain_db& chain, uint32_t from_block_num = 0 );
           void mark_as_spent( const output_reference& r );
           void dump();

        private:
           std::unique_ptr<detail::wallet_impl> my;
   };
} } // bts::blockchain
