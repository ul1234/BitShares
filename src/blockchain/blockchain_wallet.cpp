#include <bts/blockchain/blockchain_wallet.hpp>
#include <bts/blockchain/asset.hpp>
#include <bts/blockchain/block.hpp>
#include <bts/extended_address.hpp>
#include <bts/config.hpp>
#include <bts/pts_address.hpp>
#include <bts/bitcoin_wallet.hpp>
#include <unordered_map>
#include <map>
#include <fc/filesystem.hpp>
#include <fc/io/raw.hpp>
#include <fc/io/json.hpp>
#include <fc/log/logger.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/crypto/aes.hpp>
#include <sstream>

#include <iostream>

namespace bts { namespace blockchain {
   /** 
    * this is the data that is stored on disk in an encrypted form protected by
    * the wallet password.
    */
   struct wallet_data 
   {
       uint32_t                                                 version;
       uint32_t                                                 last_used_key;
       uint32_t                                                 last_scanned_block_num;
       std::unordered_map<bts::address,std::string>             recv_addresses;
       std::unordered_map<bts::pts_address,bts::address>        recv_pts_addresses;
       std::unordered_map<bts::address,std::string>             send_addresses;

       //std::vector<fc::ecc::private_key>                 keys;
       // an aes encrypted std::unordered_map<bts::address,fc::ecc::private_key>
       std::vector<char>                                        encrypted_keys;
       std::vector<char>                                        encrypted_base_key;

       std::unordered_map<bts::address,fc::ecc::private_key>    get_keys( const std::string& password )
       { try {
          ilog( "get_keys with password '${pass}'", ("pass",password) );
          std::unordered_map<bts::address, fc::ecc::private_key> keys;
          if( encrypted_keys.size() == 0 ) return keys;
          ilog( "encrypted keys.size: ${s}", ("s",encrypted_keys.size() ) );

          auto plain_txt = fc::aes_decrypt( fc::sha512::hash( password.c_str(), password.size() ), encrypted_keys );
          ilog( "plain_txt '${p}' size ${s}", ("p",plain_txt)("s",plain_txt.size()) );
          fc::datastream<const char*> ds(plain_txt.data(),plain_txt.size());
          fc::raw::unpack( ds, keys );
          return keys;
       } FC_RETHROW_EXCEPTIONS( warn, "" ) }

       extended_private_key                                     get_base_key( const std::string& password )
       {
          ilog( "get_base_key  with password '${pass}'  encrypted_base_key ${ebk}", ("pass",password)("ebk",encrypted_base_key.size()) );
          extended_private_key base_key;
          if( encrypted_base_key.size() == 0 ) return base_key;

          auto plain_txt = fc::aes_decrypt( fc::sha512::hash( password.c_str(), password.size() ), encrypted_base_key );
          return fc::raw::unpack<extended_private_key>( plain_txt );
       }

       void set_keys( const std::unordered_map<bts::address,fc::ecc::private_key>& k, const std::string& password )
       {
          auto plain_txt = fc::raw::pack( k );
          ilog( "new_password '${p}'  plaint_txt '${pt}' size ${s}", ("p",password)("pt",plain_txt)("s",plain_txt.size()) );
          encrypted_keys = fc::aes_encrypt( fc::sha512::hash( password.c_str(), password.size() ), plain_txt );
          FC_ASSERT( k == get_keys(password) );
       }

       void change_password( const std::string& old_password, const std::string& new_password )
       {
          set_keys( get_keys( old_password ), new_password );
          set_base_key( get_base_key( old_password ), new_password );
       }

       void set_base_key( const extended_private_key& bk, const std::string& new_password )
       {
          auto plain_txt = fc::raw::pack( bk );
          ilog( "new_password '${p}'  plaint_txt ${pt}", ("p",new_password)("pt",plain_txt) );
          encrypted_base_key = fc::aes_encrypt( fc::sha512::hash( new_password.c_str(), new_password.size() ), plain_txt );
          auto check = fc::aes_decrypt( fc::sha512::hash( new_password.c_str(), new_password.size() ), encrypted_base_key );
          FC_ASSERT( check == plain_txt );
       }

       // 
       std::unordered_map<transaction_id_type, transaction_state> transactions;
   };
} } // bts::blockchain


FC_REFLECT( bts::blockchain::wallet_data, 
            (version)
            (last_used_key)
            (last_scanned_block_num)
            (recv_addresses)
            (recv_pts_addresses)
            (send_addresses)
            (encrypted_base_key)
            (encrypted_keys)
            (transactions) 
            )

namespace bts { namespace blockchain {
  
   output_index::operator std::string()const
   {
      std::stringstream ss;
      ss<<block_idx<<"."<<trx_idx<<"."<<output_idx;
      return ss.str();
   }

   namespace detail 
   {
      class wallet_impl
      {
          public:
              wallet_impl():_stake(0),_current_head_idx(0){}
              std::string _wallet_base_password; // used for saving/loading the wallet
              std::string _wallet_key_password;  // used to access private keys

              fc::path                                                   _wallet_dat;
              wallet_data                                                _data;
              asset                                                      _current_fee_rate;
              uint64_t                                                   _stake;
              uint32_t                                                   _current_head_idx;

              std::map<output_index, output_reference>                   _output_index_to_ref;
              std::unordered_map<output_reference, output_index>         _output_ref_to_index;

              // keep sorted so we spend oldest first to maximize CDD
              std::map<output_index, trx_output>                         _unspent_outputs;
              std::map<output_index, trx_output>                         _spent_outputs;

              // maps address to private key index
              std::unordered_map<bts::address,fc::ecc::private_key>      _my_keys;
              std::unordered_map<transaction_id_type,signed_transaction> _id_to_signed_transaction;

              asset get_balance( asset::type balance_type )
              {
                   asset total_bal( static_cast<uint64_t>(0ull), balance_type);
                   std::vector<trx_input> inputs;
                   for( auto itr = _unspent_outputs.begin(); itr != _unspent_outputs.end(); ++itr )
                   {
                      //ilog( "unspent outputs ${o}", ("o",*itr) );
                       if( itr->second.claim_func == claim_by_signature && itr->second.amount.unit == balance_type )
                       {
                           total_bal += itr->second.amount; // TODO: apply interest earned 
                       }
                   }
                   return total_bal;
              }

              std::vector<trx_input> collect_coindays( uint64_t request_cdd, asset& total_in, 
                                                       std::unordered_set<bts::address>& req_sigs, uint64_t& provided_cdd )
              {
                   FC_ASSERT( _current_head_idx > 0 );
                   provided_cdd = 0;
                   std::vector<trx_input> inputs;
                   for( auto itr = _unspent_outputs.begin(); itr != _unspent_outputs.end(); ++itr )
                   {
                       ilog( "unspent outputs ${o}", ("o",*itr) );
                       if( itr->second.claim_func == claim_by_signature && itr->second.amount.unit == asset::bts )
                       {
                           inputs.push_back( trx_input( _output_index_to_ref[itr->first] ) );
                           total_in += itr->second.amount;
                           auto cdd = itr->second.amount.get_rounded_amount() * (_current_head_idx - itr->first.block_idx);
                           if( cdd > 0 ) 
                           {
                              provided_cdd += cdd;
                              req_sigs.insert( itr->second.as<claim_by_signature_output>().owner );
                             // ilog( "total in ${in}  min ${min}", ( "in",total_in)("min",min_amnt) );
                              if( provided_cdd >= request_cdd )
                              {
                                 return inputs;
                              }
                           }
                       }
                       else if( itr->second.claim_func == claim_by_pts && itr->second.amount.unit == asset::bts )
                       {
                           inputs.push_back( trx_input( _output_index_to_ref[itr->first] ) );
                           total_in += itr->second.amount;
                           auto cdd = itr->second.amount.get_rounded_amount() * (_current_head_idx - itr->first.block_idx);
                           if( cdd > 0 ) 
                           {
                              provided_cdd += cdd;
                              req_sigs.insert( _data.recv_pts_addresses[itr->second.as<claim_by_pts_output>().owner] );
                              if( provided_cdd >= request_cdd )
                              {
                                 return inputs;
                              }
                           }
                       }
                   }
                   return inputs;
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
                       if( itr->second.claim_func == claim_by_signature && itr->second.amount.unit == min_amnt.unit )
                       {
                           inputs.push_back( trx_input( _output_index_to_ref[itr->first] ) );
                           total_in += itr->second.amount;
                           req_sigs.insert( itr->second.as<claim_by_signature_output>().owner );
                           ilog( "total in ${in}  min ${min}", ( "in",total_in)("min",min_amnt) );
                           if( total_in.get_rounded_amount() >= min_amnt.get_rounded_amount() )
                           {
                              return inputs;
                           }
                       }
                       else if( itr->second.claim_func == claim_by_pts && itr->second.amount.unit == min_amnt.unit )
                       {
                           inputs.push_back( trx_input( _output_index_to_ref[itr->first] ) );
                           total_in += itr->second.amount;
                           req_sigs.insert( _data.recv_pts_addresses[itr->second.as<claim_by_pts_output>().owner] );
                           ilog( "total in ${in}  min ${min}", ( "in",total_in)("min",min_amnt) );
                           if( total_in.get_rounded_amount() >= min_amnt.get_rounded_amount() )
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
                           if( cbc.payoff.unit == unit )
                           {
                              total_due += cbc.payoff; 
                              total_collat += itr->second.amount;
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
                           if( cbc.payoff.unit == min_amnt.unit )
                           {
                              //asset payoff( cbc.payoff_amount, min_amnt.unit );
                              inputs.insert( std::pair<price,trx_input>( cbc.payoff / itr->second.amount, trx_input( _output_index_to_ref[itr->first] )  ) );

                           }
                       }
                   }

                   std::vector<trx_input> results;
                   for( auto ritr = inputs.rbegin(); ritr != inputs.rend(); ++ritr )
                   {
                       auto out = get_cover_output( ritr->second.output_ref ); 
                       auto cover_out = out.as<claim_by_cover_output>();
                       asset payoff = cover_out.payoff;//( cover_out.payoff_amount, cover_out.payoff_unit );

                       total_payoff += payoff;
                       total_collat += out.amount;
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
                  auto refitr = _output_ref_to_index.find(r);
                  FC_ASSERT( refitr != _output_ref_to_index.end() );
                  auto itr = _unspent_outputs.find(refitr->second);
                  FC_ASSERT( itr != _unspent_outputs.end() );
                  FC_ASSERT( itr->second.claim_func = claim_by_cover );
                  return itr->second;
              } FC_RETHROW_EXCEPTIONS( warn, "unable to find ${r}", ("r",r) ) }


              /** completes a transaction signing it and logging it, this is different than wallet::sign_transaction which
               *  merely signs the transaction without checking anything else or storing the transaction.
               **/
              void sign_transaction( signed_transaction& trx, const std::unordered_set<address>& addresses, bool mark_output_as_used = true)
              {
                   trx.stake = _stake;
                   trx.timestamp = fc::time_point::now();
                   for( auto itr = addresses.begin(); itr != addresses.end(); ++itr )
                   {
                      self->sign_transaction( trx, *itr );
                   }
                   if( mark_output_as_used )
                   {
                      for( auto itr = trx.inputs.begin(); itr != trx.inputs.end(); ++itr )
                      {
                          elog( "MARK AS SPENT ${B}", ("B",itr->output_ref) );
                          self->mark_as_spent( itr->output_ref );
                      }
                      _data.transactions[trx.id()].trx = trx;
                   }
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
      try {
        save();
      } catch ( const fc::exception& e )
      {
         wlog( "unhandled exception while saving wallet ${e}", ("e",e.to_detail_string()) );
      }
   }

   void wallet::open( const fc::path& wallet_dat, const fc::string& password )
   { try {
      my->_wallet_dat           = wallet_dat;
      my->_wallet_base_password = password;

      FC_ASSERT( fc::exists( wallet_dat ), "", ("wallet_dat",wallet_dat) )

      if( password == std::string() )
      {
         my->_data = fc::json::from_file<bts::blockchain::wallet_data>( wallet_dat );
      }
      else
      {
         std::vector<char> plain_txt = aes_load( wallet_dat, fc::sha512::hash( password.c_str(), password.size() ) );
         FC_ASSERT( plain_txt.size() > 0 );
         std::string str( plain_txt.begin(), plain_txt.end() );
         my->_data = fc::json::from_string(str).as<wallet_data>();
      }
   } FC_RETHROW_EXCEPTIONS( warn, "unable to load wallet ${wal}", ("wal",wallet_dat) ) }

   void wallet::create( const fc::path& wallet_dat, const fc::string& base_password, const fc::string& key_password, bool is_brain )
   { try {
      FC_ASSERT( !fc::exists( wallet_dat ), "", ("wallet_dat",wallet_dat) );
      FC_ASSERT( key_password.size() > 8 );

      my->_data = wallet_data();

      my->_wallet_dat = wallet_dat;
      my->_wallet_base_password = base_password;
      my->_wallet_key_password  = key_password;
      
      if( is_brain )
      {
         FC_ASSERT( base_password.size() > 8 );
         my->_data.set_base_key( extended_private_key( fc::sha256::hash( key_password.c_str(), key_password.size() ),
                                                             fc::sha256::hash( base_password.c_str(), base_password.size() ) ), key_password );
      }
      else
      {
         my->_data.set_base_key( extended_private_key( fc::ecc::private_key::generate().get_secret(),
                                                       fc::ecc::private_key::generate().get_secret() ), key_password );
      }
      my->_data.set_keys( std::unordered_map<bts::address,fc::ecc::private_key>(), key_password );
      save();
   } FC_RETHROW_EXCEPTIONS( warn, "unable to create wallet ${wal}", ("wal",wallet_dat) ) }

   void wallet::backup_wallet( const fc::path& backup_path )
   { try {
      FC_ASSERT( !fc::exists( backup_path ) );
      auto tmp = my->_wallet_dat;
      my->_wallet_dat = backup_path;
      try {
        save();
        my->_wallet_dat = tmp;
      } 
      catch ( ... )
      {
        my->_wallet_dat = tmp;
        throw;
      }
   } FC_RETHROW_EXCEPTIONS( warn, "unable to backup to ${path}", ("path",backup_path) ) }

   /**
    *  @note no balances will show up unless you scan the chain after import... perhaps just scan the
    *  genesis block which is the only place where PTS and BTC addresses should be found.
    */
   void wallet::import_bitcoin_wallet( const fc::path& wallet_dat, const std::string& passphrase )
   { try {
      auto priv_keys = bts::import_bitcoin_wallet(  wallet_dat, passphrase );
      for( auto key : priv_keys )
      {
         import_key( key, "bitcoin_import" );
         my->_data.recv_pts_addresses[ bts::pts_address( key.get_public_key() ) ] = bts::address( key.get_public_key() );
      }
   } FC_RETHROW_EXCEPTIONS( warn, "Unable to import bitcoin wallet ${wallet_dat}", ("wallet_dat",wallet_dat) ) }


   void wallet::save()
   { try {
      ilog( "saving wallet\n" );
      auto wallet_json = fc::json::to_pretty_string( my->_data );
      std::vector<char> data( wallet_json.begin(), wallet_json.end() );

      if( fc::exists( my->_wallet_dat ) )
      {
        auto new_tmp = fc::unique_path();
        auto old_tmp = fc::unique_path();
        if( my->_wallet_base_password.size() )
        {
          fc::aes_save( new_tmp, fc::sha512::hash( my->_wallet_base_password.c_str(), my->_wallet_base_password.size() ), data );
        }
        else
        {
           fc::json::save_to_file( my->_data, new_tmp, true );
        }
        fc::rename( my->_wallet_dat, old_tmp );
        fc::rename( new_tmp, my->_wallet_dat );
        fc::remove( old_tmp );
      }
      else
      {
         if( my->_wallet_base_password.size() != 0 )
         {
            fc::aes_save( my->_wallet_dat, fc::sha512::hash( my->_wallet_base_password.c_str(), my->_wallet_base_password.size() ), data );
         }
         else
         {
            fc::json::save_to_file( my->_data, my->_wallet_dat, true );
         }
      }
   } FC_RETHROW_EXCEPTIONS( warn, "Unable to save wallet ${wallet}", ("wallet",my->_wallet_dat) ) }

   asset wallet::get_balance( asset::type t )
   {
      return my->get_balance(t);
   }
   asset wallet::get_margin( asset::type t, asset& collat )
   {
      return my->get_margin_balance( t, collat );
   }

   void           wallet::set_stake( uint64_t stake, uint32_t head_idx )
   {
      wlog( "STAKE ${S}", ("S",stake) );
      my->_stake = stake;
      my->_current_head_idx = head_idx;
   }

   bts::address   wallet::import_key( const fc::ecc::private_key& key, const std::string& label )
   { try {
      auto keys = my->_data.get_keys( my->_wallet_key_password );
      auto addr = bts::address(key.get_public_key());
      keys[addr] = key;
      my->_data.set_keys( keys, my->_wallet_base_password );
      my->_data.recv_addresses[addr] = label;
      save();
      return addr;
   } FC_RETHROW_EXCEPTIONS( warn, "unable to import private key" ) }

   bts::address   wallet::new_recv_address( const std::string& label )
   { try {
      FC_ASSERT( !is_locked() );
      my->_data.last_used_key++;
      auto base_key = my->_data.get_base_key( my->_wallet_key_password );
      auto new_key = base_key.child( my->_data.last_used_key );
      return import_key(new_key, label);
   } FC_RETHROW_EXCEPTIONS( warn, "unable to create new address with label '${label}'", ("label",label) ) } 

   void wallet::add_send_address( const bts::address& addr, const std::string& label )
   { try {
      my->_data.send_addresses[addr] = label;
      save();
   } FC_RETHROW_EXCEPTIONS( warn, "unable to add send address ${addr} with label ${label}", ("addr",addr)("label",label) ) }

   std::unordered_map<bts::address,std::string> wallet::get_recv_addresses()const
   {
      return my->_data.recv_addresses;
   }
   std::unordered_map<bts::address,std::string> wallet::get_send_addresses()const
   {
      return my->_data.send_addresses;
   }

   void                  wallet::set_fee_rate( const asset& pts_per_byte )
   {
      my->_current_fee_rate = pts_per_byte;
   }

   void                  wallet::unlock_wallet( const std::string& key_password )
   { try {
      my->_data.get_base_key( key_password );
      my->_wallet_key_password = key_password;
   } FC_RETHROW_EXCEPTIONS( warn, "unable to unlock wallet" ) }
   void                  wallet::lock_wallet()
   {
      my->_wallet_base_password = std::string();
   }
   bool   wallet::is_locked()const { return my->_wallet_key_password.size() == 0; }

   signed_transaction    wallet::collect_coindays( uint64_t cdd, uint64_t& cdd_collected, const std::string& label )
   { try {
       auto   change_address = new_recv_address( label );
       std::unordered_set<bts::address> req_sigs; 
       asset  total_in(static_cast<uint64_t>(0ull),asset::bts);
       signed_transaction trx; 
       trx.inputs    = my->collect_coindays( cdd, total_in, req_sigs, cdd_collected );
       asset change = total_in;
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change) );

       trx.sigs.clear();
       my->sign_transaction( trx, req_sigs, false );

       uint64_t trx_bytes = fc::raw::pack( trx ).size();
       asset    fee( my->_current_fee_rate * trx_bytes );
       FC_ASSERT( total_in > fee );
       trx.outputs.back() = trx_output( claim_by_signature_output( change_address ), change - fee );

       trx.sigs.clear();
       my->sign_transaction(trx, req_sigs, false);
       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "", ("cdd",cdd)("collected",cdd_collected) ) }


   signed_transaction    wallet::transfer( const asset& amnt, const bts::address& to, const std::string& memo )
   { try {
       auto   change_address = new_recv_address( "change: " + memo );

       std::unordered_set<bts::address> req_sigs; 
       asset  total_in(static_cast<uint64_t>(0ull),amnt.unit);

       signed_transaction trx; 
       trx.inputs    = my->collect_inputs( amnt, total_in, req_sigs );

       asset change = total_in - amnt;

       trx.outputs.push_back( trx_output( claim_by_signature_output( to ), amnt) );
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change) );

       trx.sigs.clear();
       my->sign_transaction( trx, req_sigs, false );

       uint64_t trx_bytes = fc::raw::pack( trx ).size();
       asset    fee( my->_current_fee_rate * trx_bytes );
       ilog( "required fee ${f}", ( "f",fee ) );

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
      auto ref_itr = my->_output_ref_to_index.find(r);
      if( ref_itr == my->_output_ref_to_index.end() ) 
      {
         return;
      }

      auto itr = my->_unspent_outputs.find(ref_itr->second);
      if( itr == my->_unspent_outputs.end() )
      {
          return;
      }
      my->_spent_outputs[ref_itr->second] = itr->second;
      my->_unspent_outputs.erase(ref_itr->second);      
   }

   void wallet::sign_transaction( signed_transaction& trx, const bts::address& addr )
   { try {
      ilog( "Sign ${trx}  ${addr}", ("trx",trx.id())("addr",addr));
      FC_ASSERT( my->_wallet_key_password.size() );
      auto keys = my->_data.get_keys( my->_wallet_key_password );
      auto priv_key_itr = keys.find(addr);
      FC_ASSERT( priv_key_itr != keys.end() );
      trx.sign( priv_key_itr->second );
   } FC_RETHROW_EXCEPTIONS( warn, "unable to sign transaction ${trx} for ${addr}", ("trx",trx)("addr",addr) ) }

   /** When bidding on an asset you specify the asset you have and the price you would like
    * to sell it at.
    */
   signed_transaction    wallet::bid( const asset& amnt, const price& ratio )
   { try {
       auto   change_address = new_recv_address( "bid change: " + std::string(amnt) + " at " + std::string(ratio) );

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
       my->sign_transaction( trx, req_sigs, false );

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
       auto   change_address = new_recv_address("short sell change");

       auto bts_in = amnt;

       signed_transaction trx; 
       std::unordered_set<bts::address> req_sigs; 
       asset  total_in;

       asset in_with_fee = bts_in; // TODO: add fee proportional to trx size...??

       trx.inputs    = my->collect_inputs( in_with_fee, total_in, req_sigs );
       asset change  = total_in - bts_in;

       trx.outputs.push_back( trx_output( claim_by_long_output( change_address, ratio ), amnt) );
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change) );

       trx.sigs.clear();
       my->sign_transaction( trx, req_sigs, false );

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


   /******************************************************************
    *
    *    CANCEL BID
    *
    *****************************************************************/
   signed_transaction    wallet::cancel_bid( const output_index& bid_idx )
   { try { 
       signed_transaction trx; 
       std::unordered_set<bts::address> req_sigs; 
       auto bid_out_itr = my->_unspent_outputs.find(bid_idx);
       FC_ASSERT( bid_out_itr != my->_unspent_outputs.end() );

       auto bid_out_ref = my->_output_index_to_ref.find(bid_idx);
       FC_ASSERT( bid_out_ref != my->_output_index_to_ref.end() );
       trx.inputs.push_back( trx_input( bid_out_ref->second ) );
       if( bid_out_itr->second.claim_func == claim_by_bid )
       {
          auto bid_out = bid_out_itr->second.as<claim_by_bid_output>();
          asset fee( my->_current_fee_rate * 500 );//, asset::bts );
          if( bid_out_itr->second.amount.unit == fee.unit )
          {
             if( fee < bid_out_itr->second.amount )
             {
                trx.outputs.push_back( trx_output( claim_by_signature_output( bid_out.pay_address ), 
                                                   bid_out_itr->second.amount - fee ) );
             }
          }
          else
          {
             // collect inputs for fee here
             asset  fee_in;
             fee = fee + fee; // double the fee just to be sure 
             auto fee_inputs = my->collect_inputs( fee, fee_in, req_sigs );
             trx.outputs.push_back( trx_output( claim_by_signature_output( bid_out.pay_address ), 
                                                   fee_in - fee ) );

             trx.outputs.push_back( trx_output( claim_by_signature_output( bid_out.pay_address ), 
                                                   bid_out_itr->second.amount ) );
          }
          req_sigs.insert( bid_out.pay_address);
       }
       else if( bid_out_itr->second.claim_func == claim_by_long )
       {
          auto bid_out = bid_out_itr->second.as<claim_by_long_output>();

          // subtract standard fee from amount..
          // TODO: assuming 500 is greater than the size of this transaction, over estimate..
          // we may be able to reduce this 
          asset fee( my->_current_fee_rate * 500);//, asset::bts );
          if( bid_out_itr->second.amount > fee )
          {
             trx.outputs.push_back( trx_output( claim_by_signature_output( bid_out.pay_address ), 
                                                bid_out_itr->second.amount - fee ) );
          }
          req_sigs.insert( bid_out.pay_address);
       }
       

       my->sign_transaction( trx, req_sigs );

       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "unable to find bid", ("bid",bid_idx) ) }
   signed_transaction    wallet::cancel_bid( const output_reference& bid )
   { try {
       auto bid_idx_itr = my->_output_ref_to_index.find(bid);
       FC_ASSERT( bid_idx_itr != my->_output_ref_to_index.end() );
       return cancel_bid( bid_idx_itr->second );
   } FC_RETHROW_EXCEPTIONS( warn, "unable to find bid", ("bid",bid) ) }



   /**
    *  Builds a transaction to cover amnt of short positions starting with the highest price
    *  first and working down.
    */
   signed_transaction    wallet::cover( const asset& amnt )
   { try {
       wlog( "Cover ${amnt}", ("amnt",amnt) );
       auto   change_address = new_recv_address("cover change");
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

          asset payoff = cover_out.payoff;//( cover_out.payoff_amount, cover_out.payoff_unit );

          wlog( "Payoff ${amnt}  Collateral ${c}", ("amnt",amnt)("c",txout.amount) );

          // if remaining > itr->owed then free 100% of the collateral and remaining -= itr->owed
          if( remaining >= payoff )
          {
             freed_collateral += txout.amount;
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

              freed_collateral += txout.amount - leftover_collateral; //remaining * price;

              if( leftover_debt.get_rounded_amount() )
              {
                 freed_collateral.amount *= 7; // always increase margin when doing a cover...
                 freed_collateral.amount /= 8; // always increase margin when doing a cover...
                 if( freed_collateral > collat_in ) // cannot free more than we have to start
                 {
                     freed_collateral = asset(0.0,asset::bts);
                 }
                 trx.outputs.push_back( trx_output( claim_by_cover_output( leftover_debt, cover_out.owner ), 
                                                    collat_in - freed_collateral ) );
              }
              break;
          }
       }
       // if remaining > 0 then change += remaining.

       const fc::uint128_t zero(0);

       if( freed_collateral.get_rounded_amount() != 0 )
          trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), freed_collateral ) );
       if( change.get_rounded_amount() != 0 )
          trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change) );

       ilog( "req sigs ${sigs}", ("sigs",req_sigs) );
       my->sign_transaction( trx, req_sigs, false );
       auto fees_due = my->_current_fee_rate * trx.size() * 2;
       trx.sigs.clear();

       // pay fees..
       asset total_fee_in;
       auto extra_in = my->collect_inputs( fees_due, total_fee_in, req_sigs );
       trx.inputs.insert( trx.inputs.end(), extra_in.begin(), extra_in.end() );
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), total_fee_in - fees_due ) );

       my->sign_transaction( trx, req_sigs );
       return trx;
   } FC_RETHROW_EXCEPTIONS( warn, "${asset}", ("asset",amnt) ) }

   signed_transaction wallet::add_margin( const asset& collateral_amount, asset::type u )
   { try {
       FC_ASSERT( collateral_amount.unit == asset::bts );
       FC_ASSERT( u != asset::bts );

       auto   change_address = new_recv_address( "add margin change");

       signed_transaction trx;
       std::unordered_set<bts::address> req_sigs; 
       asset  total_in(static_cast<uint64_t>(0ull),u);
       asset  cover_in(static_cast<uint64_t>(0ull),u);
       asset  collat_in(static_cast<uint64_t>(0ull),asset::bts);

       trx.inputs   = my->collect_inputs( collateral_amount, total_in, req_sigs );
       asset change = total_in - collateral_amount;

       auto cover_inputs  = my->collect_cover_inputs( asset(), collat_in, cover_in, req_sigs );
       trx.inputs.insert( trx.inputs.end(), cover_inputs.begin(), cover_inputs.end() );

       trx.outputs.push_back( trx_output( claim_by_cover_output( cover_in, change_address ), collat_in + collateral_amount ) );
       trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change ) );

       my->sign_transaction( trx, req_sigs, false );
       auto trx_fees = my->_current_fee_rate * trx.size();
       trx.outputs.clear();

       if( change > trx_fees )
       {
          trx.outputs.push_back( trx_output( claim_by_signature_output( change_address ), change - trx_fees ) );
       }
       else
       {
          trx.outputs.push_back( trx_output( claim_by_cover_output( cover_in, change_address ), 
                                             collat_in + collateral_amount - trx_fees) );
       }

       trx.sigs.clear();
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
   std::unordered_map<transaction_id_type, transaction_state> wallet::get_transaction_history()const
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
                  const trx_output& out   = trx.outputs[out_idx];
                  const output_reference  out_ref( trx.id(),out_idx );
                  const output_index      oidx( i, trx_idx, out_idx );
                  switch( out.claim_func )
                  {
                     case claim_by_pts:
                     {
                        auto owner = out.as<claim_by_pts_output>().owner;
                        auto aitr  = my->_data.recv_pts_addresses.find(owner); //my_addresses.find(owner);
                        if( aitr != my->_data.recv_pts_addresses.end() )
                        {
                            if( !trx.meta_outputs[out_idx].is_spent() )
                            {
                               my->_output_index_to_ref[oidx]    = out_ref;
                               my->_output_ref_to_index[out_ref] = oidx;
                               my->_unspent_outputs[oidx] = trx.outputs[out_idx];
                            }
                            else
                            {
                               mark_as_spent( out_ref ); //output_reference(trx.id(), out_idx ) );
                               //my->_spent_outputs[output_reference( trx.id(), out_idx )] = trx.outputs[out_idx];
                            }
                           // std::cerr<<"found block["<<i<<"].trx["<<trx_idx<<"].output["<<out_idx<<"]  " << std::string(trx.id()) <<" => "<<std::string(owner)<<"\n";
                           found = true;
                        }
                     }
                     case claim_by_signature:
                     {
                        auto owner = out.as<claim_by_signature_output>().owner;
                        auto aitr  = my->_data.recv_addresses.find(owner); //my_addresses.find(owner);
                        if( aitr != my->_data.recv_addresses.end() )
                        {
                            if( !trx.meta_outputs[out_idx].is_spent() )
                            {
                               my->_output_index_to_ref[oidx]    = out_ref;
                               my->_output_ref_to_index[out_ref] = oidx;
                               my->_unspent_outputs[oidx] = trx.outputs[out_idx];
                            }
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
                        auto aitr = my->_data.recv_addresses.find(bid.pay_address);
                        if( aitr != my->_data.recv_addresses.end() )
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
                               //my->_unspent_outputs[out_ref] = trx.outputs[out_idx];
                               my->_output_index_to_ref[oidx]    = out_ref;
                               my->_output_ref_to_index[out_ref] = oidx;
                               my->_unspent_outputs[oidx] = trx.outputs[out_idx];
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
                        auto aitr = my->_data.recv_addresses.find(short_sell.pay_address);
                        if( aitr != my->_data.recv_addresses.end() )
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
                               my->_output_index_to_ref[oidx]    = out_ref;
                               my->_output_ref_to_index[out_ref] = oidx;
                               my->_unspent_outputs[oidx] = trx.outputs[out_idx];
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
                        auto aitr = my->_data.recv_addresses.find(cover.owner);
                        if( aitr != my->_data.recv_addresses.end() )
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
                               //my->_unspent_outputs[out_ref] = trx.outputs[out_idx];
                               my->_output_index_to_ref[oidx]    = out_ref;
                               my->_output_ref_to_index[out_ref] = oidx;
                               my->_unspent_outputs[oidx] = trx.outputs[out_idx];
                            }
                        }
                        else
                        {
                           // skip, it doesn't belong to me
                        }
                        break;
                     }

                     case null_claim_type:
                     default:
                        FC_ASSERT( !"Invalid Claim Type" );
                        break;
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
                 std::cerr<<std::string(itr->first)<<"]  ";
                 std::cerr<<std::string(itr->second.amount)<<" ";
                 std::cerr<<fc::variant(itr->second.claim_func).as_string()<<" ";
                 std::cerr<< std::string(itr->second.as<claim_by_signature_output>().owner);
                 std::cerr<<"\n";
                 break;
              default:
                  std::cerr << "unsupported claim type "<<fc::variant(itr->second.claim_func).as_string() <<" \n";
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
                 //std::cerr<<std::string(itr->first.trx_hash)<<":"<<int(itr->first.output_idx)<<"]  ";
                 std::cerr<<std::string(itr->first)<<"]  ";
                 std::cerr<<std::string(itr->second.amount)<<" ";
                 std::cerr<<fc::variant(itr->second.claim_func).as_string()<<" ";

                 std::cerr<< std::string(itr->second.as<claim_by_bid_output>().ask_price);
                 std::cerr<< " owner: ";
                 std::cerr<< std::string(itr->second.as<claim_by_bid_output>().pay_address);
               //  std::cerr<< " min trade: "<< itr->second.as<claim_by_bid_output>().min_trade;
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
                 //std::cerr<<std::string(itr->first.trx_hash)<<":"<<int(itr->first.output_idx)<<"]  ";
                 std::cerr<<std::string(itr->first)<<"]  ";
                 std::cerr<<std::string(itr->second.amount)<<" ";
                 std::cerr<<fc::variant(itr->second.claim_func).as_string()<<" ";
                 std::cerr<< std::string(itr->second.as<claim_by_long_output>().ask_price);
                 std::cerr<< " owner: ";
                 std::cerr<< std::string(itr->second.as<claim_by_long_output>().pay_address);
                 //std::cerr<< " min trade: "<< itr->second.as<claim_by_long_output>().min_trade;
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
                // std::cerr<<std::string(itr->first.trx_hash)<<":"<<int(itr->first.output_idx)<<"]  ";
                 std::cerr<<std::string(itr->first)<<"]  ";
                 std::cerr<<std::string(itr->second.amount)<<" ";
                 std::cerr<<fc::variant(itr->second.claim_func).as_string()<<" ";

                 auto cover = itr->second.as<claim_by_cover_output>();
                 auto payoff = cover.payoff;//asset(cover.payoff_amount,cover.payoff_unit);
                 auto payoff_threshold = cover.get_call_price( itr->second.amount ); //asset(uint64_t(cover.payoff_amount*double(1.5)*COIN),cover.payoff_unit);
                 std::cerr<< std::string(payoff);
                 std::cerr<< " owner: ";
                 std::cerr<< std::string(itr->second.as<claim_by_cover_output>().owner);
                 // this is the break even price... we actually need to cover at half the price?
                 std::cerr<< " price: " << std::string(payoff_threshold);
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
