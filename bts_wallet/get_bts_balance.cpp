#include <fc/crypto/ripemd160.hpp>
#include "chain_server.hpp" 
#include <bts/bitcoin_wallet.hpp>
#include "chain_connection.hpp"
#include "chain_messages.hpp"
#include <fc/reflect/reflect.hpp>
#include <fc/io/console.hpp>
#include <mail/message.hpp>
#include <mail/stcp_socket.hpp>
#include <bts/blockchain/blockchain_db.hpp>
#include <bts/db/level_map.hpp>
#include <fc/time.hpp>
#include <fc/network/tcp_socket.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/thread/thread.hpp>
#include <fc/thread/future.hpp>
#include <fc/io/raw.hpp>
#include <fc/io/json.hpp>
#include <fc/log/logger.hpp>

#include <iostream>

#include <algorithm>
#include <unordered_map>
#include <map>

struct genesis_block_config
{
   genesis_block_config():supply(0),blockheight(0){}
   double                                            supply;
   uint64_t                                          blockheight;
   std::unordered_map<bts::pts_address,uint64_t >    balances;
};
FC_REFLECT( genesis_block_config, (supply)(balances) )


int main( int argc, char** argv )
{
   try {
      if( argc != 2 )
      {
         std::cerr<<"usage:  "<<argv[0]<<"  wallet.dat\n";
         return -1;
      }
      FC_ASSERT( fc::exists( "genesis.json" ) );

      auto config = fc::json::from_file( "genesis.json" ).as<genesis_block_config>();
      std::cout << "bitcoin wallet passphrase: ";
      fc::set_console_echo( false );
      std::string phrase;
      std::getline( std::cin, phrase );
      fc::set_console_echo( true );
      auto keys   = bts::import_bitcoin_wallet( fc::path( argv[1] ), phrase );
      std::cout << "\nLoaded "<<keys.size()<<" keys... searching for balances\n";
      uint64_t balance = 0;
      for( auto itr = keys.begin(); itr != keys.end(); ++itr )
      {
         {
          auto addr = bts::pts_address( itr->get_public_key(), false, 0 );
          auto bitr = config.balances.find(addr);
          if( bitr != config.balances.end() ) balance += bitr->second;
         }
         {
          auto addr = bts::pts_address( itr->get_public_key(), true, 0 );
          auto bitr = config.balances.find(addr);
          if( bitr != config.balances.end() ) balance += bitr->second;
         }
         {
          auto addr = bts::pts_address( itr->get_public_key(), false );
          auto bitr = config.balances.find(addr);
          if( bitr != config.balances.end() ) balance += bitr->second;
         }
         {
          auto addr = bts::pts_address( itr->get_public_key(), true );
          auto bitr = config.balances.find(addr);
          if( bitr != config.balances.end() ) balance += bitr->second;
         }
         std::cout<<"balance: "<< double(balance)/COIN <<"\r";
      }
      std::cout<<"\n";
   } 
   catch ( const fc::exception& e )
   {
       std::cerr<<e.to_detail_string()<<"\n";
       return -1;
   }

   return 0;
}
