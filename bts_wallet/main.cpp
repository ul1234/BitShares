#include <iostream>
#include <sstream>
#include <iomanip>
#include <fc/filesystem.hpp>
#include <bts/blockchain/blockchain_wallet.hpp>
#include <fc/thread/thread.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/log/file_appender.hpp>
#include <fc/log/logger_config.hpp>
#include <bts/config.hpp>
#include <fc/io/raw.hpp>
#include <fc/io/json.hpp>
#include <fc/log/logger.hpp>
#include <fstream>
#include <bts/blockchain/blockchain_printer.hpp>
#include "chain_connection.hpp"
#include "chain_messages.hpp"
#include <fc/network/tcp_socket.hpp>
#include <fc/rpc/json_connection.hpp>
#ifndef WIN32
#include <readline/readline.h>
#include <readline/history.h>
#endif //!WIN32

using namespace bts::blockchain;

class client_delegate
{

};

std::string to_balance( uint64_t a )
{
    uint64_t fraction = a % COIN;
    auto fract_str = fc::to_string(static_cast<uint64_t>(fraction+COIN)).substr(1);
    return fc::to_string( uint64_t(a/COIN) ) + "." + fract_str;
}

struct client_config
{
    client_config()
    :rpc_port(5678)
    {
        //unique_node_list["162.243.45.158:4567"] = "";
        unique_node_list["127.0.0.1:4567"] = "";
    }

    uint16_t rpc_port;
    std::string rpc_user;
    std::string rpc_password;

    /// map "IP:PORT" to "publickey" of the node that we are connecting to.
    std::unordered_map<std::string,std::string> unique_node_list;
};
FC_REFLECT( client_config, (rpc_port)(rpc_user)(rpc_password)(unique_node_list) )

class client : public chain_connection_delegate
{
   public:
      void on_connection_disconnected( chain_connection& c )
      {
          chain_connect_loop_complete = fc::async( 
                [this](){ fc::usleep(fc::seconds(1)); chain_connect_loop(); } );
      }
      fc::tcp_server                                _tcp_serv;
      fc::future<void>                              _accept_loop_complete;

      // TODO: clean up memory leak where we never remove items from this set because
      // we do not detect RPC disconnects
      std::unordered_set<fc::rpc::json_connection*> _login_set;
      client_config                                 _config;
      std::unordered_map<bts::blockchain::transaction_id_type,bts::blockchain::signed_transaction> pending;

      ~client()
      {
           try {
               if( chain_connect_loop_complete.valid() )
               {
                  try {
                     _chain_con.close();
                     chain_connect_loop_complete.cancel();
                     chain_connect_loop_complete.wait();
                  } 
                  catch( fc::exception& e )
                  {
                    wlog( "unhandled exception thrown in destructor.\n${e}", ("e", e.to_detail_string() ) );
                  }
               }
               _tcp_serv.close();
               if( _accept_loop_complete.valid() )
               {
                  _accept_loop_complete.cancel();
                  _accept_loop_complete.wait();
               }
           } 
           catch ( const fc::canceled_exception& ){}
           catch ( const fc::exception& e )
           {
              wlog( "unhandled exception thrown in destructor.\n${e}", ("e", e.to_detail_string() ) );
           }
      }

      void start_rpc_server(uint16_t port)
      {
          std::cout<<"\rlistening for rpc connections on port "<<port<<"\n";
          _tcp_serv.listen( port );
          _accept_loop_complete = fc::async( [this]{ accept_loop(); } );
      }

      void accept_loop()
      {
        while( !_accept_loop_complete.canceled() )
        {
           fc::tcp_socket_ptr sock = std::make_shared<fc::tcp_socket>();
           try 
           {
             _tcp_serv.accept( *sock );
           }
           catch ( const fc::exception& e )
           {
             elog( "fatal: error opening socket for rpc connection: ${e}", ("e", e.to_detail_string() ) );
             return;
           }

           auto buf_istream = std::make_shared<fc::buffered_istream>( sock );
           auto buf_ostream = std::make_shared<fc::buffered_ostream>( sock );

           auto json_con = std::make_shared<fc::rpc::json_connection>( std::move(buf_istream), std::move(buf_ostream) );
           register_methods( json_con );

           fc::async( [json_con]{ json_con->exec().wait(); } );
        }
      }
      void register_methods( const fc::rpc::json_connection_ptr& con )
      {
         std::cout<<"rpc login detected\n";
         // don't capture the shared ptr, it would create a circular reference
         fc::rpc::json_connection* capture_con = con.get(); 
         con->add_method( "login", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( params.size() == 2 );
             FC_ASSERT( params[0].as_string() == _config.rpc_user )
             FC_ASSERT( params[1].as_string() == _config.rpc_password )
             _login_set.insert( capture_con );
             return fc::variant( true );
         });


         con->add_method( "getmargin", [=]( const fc::variants& params ) -> fc::variant 
         {
              check_login( capture_con );
              FC_ASSERT( params.size() == 1 );
              FC_ASSERT( _chain_connected );

              asset collat;
              asset due  = _wallet.get_margin( params[0].as<asset::type>(), collat );

              fc::mutable_variant_object info; 
              info["collateral"]     = fc::variant(chain.head_block_id());
              info["owed"]           = fc::variant(due);

              collat.amount *= 3;
              collat.amount /= 4;
             // info["min_call_price"] = 
              info["avg_call_price"] = std::string( due/collat );

              return fc::variant(info);
         });

         con->add_method( "addmargin", [=]( const fc::variants& params ) -> fc::variant 
         {
              check_login( capture_con );
              FC_ASSERT( params.size() == 2 );
              FC_ASSERT( _chain_connected );

              asset collat     = params[0].as<asset>();
              FC_ASSERT( collat.unit == asset::bts );

              auto trx = _wallet.add_margin( collat, params[1].as<asset::type>() ); 
              broadcast_transaction(trx);

              return fc::variant(trx.id());
         });

         con->add_method( "getmarket", [=]( const fc::variants& params ) -> fc::variant 
         {
            FC_ASSERT( _chain_connected );
            FC_ASSERT( params.size() == 2 );

            market_data data = chain.get_market( params[0].as<asset::type>(), params[1].as<asset::type>() );
            return fc::variant(data);
         });

         con->add_method( "getnewaddress", [=]( const fc::variants& params ) -> fc::variant 
         {
             check_login( capture_con );
             return fc::variant( _wallet.get_new_address() ); 
         });

         con->add_method( "transfer", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( _chain_connected );
             check_login( capture_con );
             FC_ASSERT( params.size() == 2 );
             auto amount = params[0].as<bts::blockchain::asset>();
             auto addr   = params[1].as_string();
             auto trx = _wallet.transfer( amount, addr );
             broadcast_transaction(trx);
             return fc::variant( trx.id() ); 
         });
         con->add_method( "getbalance", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( _chain_connected );
             check_login( capture_con );
             FC_ASSERT( params.size() == 1 );
             auto unit = params[0].as<bts::blockchain::asset::type>();
             return fc::variant( _wallet.get_balance( unit ) ); 
         });
         con->add_method( "buy", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( _chain_connected );
             check_login( capture_con );
             FC_ASSERT( params.size() == 2 );
             auto amount       = params[0].as<bts::blockchain::asset>();
             auto ppu          = params[1].as<bts::blockchain::asset>();
             auto price_ratio  = ppu / asset( 1.0, amount.unit );
             auto required_input = amount * price_ratio;
             auto trx = buy( required_input, price_ratio );
             return fc::variant( trx ); 
         });
         con->add_method( "sell", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( _chain_connected );
             check_login( capture_con );
             FC_ASSERT( params.size() == 2 );
             auto amount       = params[0].as<bts::blockchain::asset>();
             auto ppu          = params[1].as<bts::blockchain::asset>();
             auto price_ratio  = ppu / asset( 1.0, amount.unit );
             auto trx = sell( amount, price_ratio );
             return fc::variant( trx ); 
         });
         con->add_method( "short_sell", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( _chain_connected );
             check_login( capture_con );
             FC_ASSERT( params.size() == 2 );
             auto amount       = params[0].as<bts::blockchain::asset>();
             auto ppu          = params[1].as<bts::blockchain::asset>();
             auto price_ratio  = ppu / asset( 1.0, amount.unit );
             auto trx = short_sell( amount, price_ratio );
             return fc::variant( trx ); 
         });
         con->add_method( "cover", [=]( const fc::variants& params ) -> fc::variant 
         {
              FC_ASSERT( _chain_connected );
              check_login( capture_con );
              FC_ASSERT( params.size() == 1 );
              auto amount = params[0].as<bts::blockchain::asset>();
              auto trx = _wallet.cover( amount );
              broadcast_transaction( trx );
              return fc::variant(trx.id());
         });

         con->add_method( "cancel_order", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( _chain_connected );
             check_login( capture_con );
             FC_ASSERT( params.size() == 2 );
             auto trx_id       = params[0].as_string();
             auto output_index = params[1].as_int64();
             auto trx = cancel_open_bid( trx_id, output_index );
             return fc::variant( trx ); 
         });

         con->add_method( "get_transaction", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( params.size() == 1 );
             return fc::variant( chain.fetch_transaction( params[0].as<transaction_id_type>() )  ); 
         });

         con->add_method( "get_block", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( params.size() == 1 );
             return fc::variant( chain.fetch_block( params[0].as_int64() )  ); 
         });

         con->add_method( "getinfo", [=]( const fc::variants& params ) -> fc::variant 
         {
             fc::mutable_variant_object info; 
             info["headblock_id"]  = fc::variant(chain.head_block_id());
             info["block_count"]   = chain.head_block_num();
             info["connected"]     = _chain_connected;
             info["bts_supply"]    = chain.current_bitshare_supply();
             return fc::variant( info );
         });

         con->add_method( "validateaddress", [=]( const fc::variants& params ) -> fc::variant 
         {
             FC_ASSERT( params.size() == 1 );
             try {
                auto test = bts::address( params[0].as_string() );
                return fc::variant(test.is_valid());
             } 
             catch ( const fc::exception& )
             {
               return fc::variant(false);
             }
         });

         con->add_method( "get_open_bids", [=]( const fc::variants& params ) -> fc::variant
         {
             check_login( capture_con );
             return fc::variant( _wallet.get_open_bids() );
         });

         con->add_method( "get_open_short_sell", [=]( const fc::variants& params ) -> fc::variant
         {
             check_login( capture_con );
             return fc::variant( _wallet.get_open_short_sell() );
         });
                          
         con->add_method( "import_bts_privkey", [=]( const fc::variants& params ) -> fc::variant 
         {
             check_login( capture_con );
             bool rescan = false;
             FC_ASSERT( params.size() == 1 );

             if( params.size() == 3 )
             {
               rescan = params[2].as<bool>();
             }
             auto hashed_parameter = fc::sha256( params[0].as_string() );
             auto private_key = fc::ecc::private_key::regenerate( hashed_parameter );
             _wallet.import_key( private_key );
             if( rescan )
             {
               _wallet.scan_chain(chain);
             }
             return fc::variant( true );
         });

      }

      void check_login( fc::rpc::json_connection* con )
      {
         if( _login_set.find( con ) == _login_set.end() )
         {
            FC_THROW_EXCEPTION( exception, "not logged in" ); 
         }
      }



      client():_chain_con(this),_chain_connected(false){}
      virtual void on_connection_message( chain_connection& c, const message& m )
      {
         if( m.type == chain_message_type::block_msg )
         {
            auto blkmsg = m.as<block_message>();
            chain.push_block( blkmsg.block_data );
            _wallet.set_stake( chain.get_stake() );
            if( _wallet.scan_chain( chain, blkmsg.block_data.block_num ) )
            {
                std::cout<<"new transactions received\n";
                print_balances();
            }
         }
         else if( m.type == trx_message::type )
         {
            auto trx_msg = m.as<trx_message>();
            chain.evaluate_signed_transaction( trx_msg.signed_trx ); // throws exception if invalid trx.
            if( pending.insert( std::make_pair(trx_msg.signed_trx.id(),trx_msg.signed_trx) ).second )
            {
               // reset the mining thread...
            }
         }
         else if( m.type == trx_err_message::type )
         {
            auto errmsg = m.as<trx_err_message>();
            std::cerr<<  errmsg.err <<"\n";
            elog( "${e}", ("e", errmsg ) );
         }
      }

      void open( const fc::path& datadir )
      {
          chain.open( datadir / "chain" );
          _wallet.open( datadir / "wallet.bts" );

         // if( chain.head_block_num() == uint32_t(-1) )
         // {
          //    auto genesis = create_test_genesis_block();
         //   ilog( "genesis block: \n${s}", ("s", fc::json::to_pretty_string(genesis) ) );
         //    chain.push_block( genesis );
         //     _wallet.scan_chain( chain, 0 );
         //     _wallet.save();
         // }
          
          if( chain.head_block_num() != uint32_t(-1) )
             _wallet.scan_chain( chain );

          // load config, connect to server, and start subscribing to blocks...
          //sim_loop_complete = fc::async( [this]() { server_sim_loop(); } );
          chain_connect_loop_complete = fc::async( [this](){ chain_connect_loop(); } );
      }

      void broadcast_transaction( const signed_transaction& trx )
      { try {
         _chain_con.send( trx_message( trx ) );
      } FC_RETHROW_EXCEPTIONS( warn, "unable to send ${trx}", ("trx",trx) ) }

      /*
      void server_sim_loop()
      { 
        try {
           while( true )
           {
              fc::usleep( fc::seconds(20) );

              auto order_trxs   = chain.match_orders(); 
              trx_queue.insert( trx_queue.end(), order_trxs.begin(), order_trxs.end() );
              if( trx_queue.size() )
              {
                 auto new_block = chain.generate_next_block( trx_queue );
                 trx_queue.clear();
                 if( new_block.trxs.size() )
                 {
                   chain.push_block( new_block );
                   handle_block( new_block.block_num );
                 }
              }
           }
        } 
        catch ( const fc::exception& e )
        {
           std::cerr<< e.to_detail_string() << "\n";
           exit(-1);
        }
      }
      */
      chain_connection _chain_con;
      bool _chain_connected;
      void chain_connect_loop()
      {
         _chain_connected = false;
         while( !chain_connect_loop_complete.canceled() )
         {
            for( auto itr = _config.unique_node_list.begin(); itr != _config.unique_node_list.end(); ++itr )
            {
                 try {
                    std::cout<< "\rconnecting to bitshares network: "<<itr->first<<"\n";
                    // TODO: pass public key to connection so we can avoid man-in-the-middle attacks
                    _chain_con.connect( fc::ip::endpoint::from_string(itr->first) );

                    subscribe_message msg;
                    msg.version        = 0;
                    if( chain.head_block_num() != uint32_t(-1) )
                    {
                       msg.last_block     = chain.head_block_id();
                    }
                    _chain_con.send( mail::message( msg ) );
                    std::cout<< "\rconnected to bitshares network\n";
                    _chain_connected = true;
                    return;
                 } 
                 catch ( const fc::exception& e )
                 {
                    std::cout<< "\runable to connect to bitshares network at this time.\n";
                    wlog( "${e}", ("e",e.to_detail_string()));
                 }
            }

            // sleep in .5 second increments so we can quit quickly without hanging
            for( uint32_t i = 0; i < 30 && !chain_connect_loop_complete.canceled(); ++i )
               fc::usleep( fc::microseconds(500000) );
         }
      }


      asset get_balance( asset::type u )
      {
          return _wallet.get_balance( asset::type(u) );
      }
      void print_balances()
      {
         for( int a = asset::bts; a < asset::count; ++a )
         {
              std::cout << std::string(_wallet.get_balance( asset::type(a) )) << "\n";
              /*
              uint64_t amount = _wallet.get_balance( asset::type(a) ).amount.high_bits();
              uint64_t fraction = amount % COIN;
              auto fract_str = fc::to_string(static_cast<uint64_t>(fraction+COIN)).substr(1);
              std::cout << (amount/COIN) <<"."<< fract_str << " " << fc::variant(asset::type(a)).as_string() << "\n";
              */
         }
         std::cout<<"\n Margin Positions\n";
         for( int a = asset::bts+1; a < asset::count; ++a )
         {
              asset collat;
              asset due  = _wallet.get_margin( asset::type(a), collat );
              uint64_t amount = due.amount.high_bits();
              uint64_t fraction = amount % COIN;
              auto fract_str = fc::to_string(static_cast<uint64_t>(fraction+COIN)).substr(1);
              auto total_collat = collat;
              collat.amount *= 3;
              collat.amount /= 4;
              std::cout << (amount/COIN) <<"."<< fract_str << " " << fc::variant(asset::type(a)).as_string();
              std::cout << "  total collateral: " << std::string( total_collat );
              std::cout << "  avg call price: " << std::string( due/collat );
              std::cout <<"\n";
         }
         _wallet.dump();
      }
      void print_market( const std::string& quote, const std::string& base, uint32_t lines = 20 )
      {
         asset::type bunit = fc::variant(base).as<asset::type>();
         asset::type qunit = fc::variant(quote).as<asset::type>();
         if( bunit > qunit ) std::swap( bunit, qunit );

         auto mark = chain.get_market( qunit, bunit );

         std::cout << std::setw( 55 ) << ("      BIDS             ") << "  |";
         std::cout << std::setw( 55 ) << ("      ASKS             ") << "  |";
     //    std::cout << std::setw( 36 ) << ("     SHORTS ("+quote+")        ");
     //    std::cout << std::setw( 36 ) << "     MARGIN     ";
         std::cout << "\n---------------------------------------------------------|---------------------------------------------------------|\n";
         for( uint32_t i = 0; i < lines; ++i )
         {
            bool end = true;
            if( mark.bids.size() > i ) 
            {
                int bid_index = mark.bids.size() - 1 - i;
                std::cout << std::setw(25) << std::string(asset( mark.bids[bid_index].amount, qunit)*mark.bids[bid_index].bid_price );
                if( !mark.bids[bid_index].is_short )
                {
                   std::cout << " " << std::setw(30) << std::string(mark.bids[bid_index].bid_price) <<" |";
                }
                else
                {
                   std::cout << " " << std::setw(30) << ("-"+std::string(mark.bids[bid_index].bid_price)) <<" |";
                }
                end = false;
            }
            else
            {
                std::cout<< std::setw( 55 ) << " " << "  |";
            }
            if( mark.asks.size() > i )
            {
                std::cout << std::setw(25) << std::string(asset( mark.asks[i].amount,bunit ) );
                std::cout << std::setw(30) << std::string(mark.asks[i].ask_price) <<"  |";
                end = false;
            }
            else
            {
                std::cout<< std::setw( 55 ) << " " << "  |";
            }
            /*
            if( mark.shorts.size() > i )
            {
                std::cout << std::setw(12) << to_balance( mark.shorts[i].amount ) << " " << std::setw(12) << std::string(mark.shorts[i].short_price) <<" |  ";
                end = false;
            }
            else
            {
                std::cout<< std::setw( 37 ) << " " << "|";
            }
            if( mark.margins.size() > i )
            {
                end = false;
            }
            else
            {
                std::cout<< std::setw( 37 ) << " " << "|";
            }
            */
            std::cout <<"\n";

            if( end ) break;
         }
      }

      void print_new_address()
      {
         std::cout<< std::string(_wallet.get_new_address()) <<"\n";
      }
	  
	  void print_wallet_address()
	  {
		  std::vector<bts::address> address=_wallet.list_address();

		  for(auto itr=address.begin();itr!=address.end();++itr)
		  {
			  std::cout<<"address:"<<std::string(*itr) <<"\n";
		  }
		   
	  }
      std::string transfer( double amnt, std::string u, std::string addr )
      {
         FC_ASSERT( _chain_connected );
         asset::type unit = fc::variant(u).as<asset::type>();
         auto trx = _wallet.transfer( asset(amnt,unit), addr );
         ilog( "${trx}", ("trx",trx) );
         broadcast_transaction( trx );
         return trx.id();
      }
      std::string short_sell( asset amnt, price p ) //double amnt, std::string u, double sellprice )
      {
         auto trx = _wallet.short_sell( amnt, p ); //bts::blockchain::price( sellprice, asset::bts, unit ) );
         std::cout<<"trx id: "<< std::string(trx.id()) <<"\n";
         ilog( "${trx}", ("trx",trx) );
         broadcast_transaction( trx );
         return trx.id();
      }

      std::string buy( asset amount, price pr )
      {
         auto trx = _wallet.bid( amount, pr );
         ilog( "${trx}", ("trx",trx) );
         broadcast_transaction( trx );
         return trx.id();
      }
      std::string sell( asset amount, price pr ) //double amnt, std::string u, double buyprice, std::string base )
      {
         auto trx = _wallet.bid( amount, pr );
         ilog( "${trx}", ("trx",trx) );
         broadcast_transaction( trx );
         return trx.id();
      }


      void dump_chain_html( std::string name )
      {
        std::ofstream html( name.c_str() );
        for( uint32_t i = 0; i <= chain.head_block_num(); ++i )
        {
           auto b = chain.fetch_trx_block(i);
           html << bts::blockchain::pretty_print( b, chain );
        }
      }
      void dump_chain_json( std::string name )
      {
          std::ofstream html( name.c_str() );
          html <<"[\n";
          for( uint32_t i = 0; i <= chain.head_block_num(); ++i )
          {
             auto b = chain.fetch_trx_block(i);
             html << fc::json::to_pretty_string( b );
             if( i != chain.head_block_num() ) html << ",\n";
          }
          html <<"]\n";
      }
      std::string cover( double amnt, std::string u )
      {
         asset::type unit = fc::variant(u).as<asset::type>();
         auto trx = _wallet.cover( asset( amnt, unit ) );
         broadcast_transaction( trx );
         return trx.id();
      }

      void print_open_orders( asset::type a )
      {
      }

      std::string cancel_open_bid( std::string h, uint32_t idx )
      { 
         auto trx = _wallet.cancel_bid( output_reference(fc::uint160(h), idx) );
         broadcast_transaction( trx );
         return trx.id();
      }


      bts::blockchain::blockchain_db    chain;
      bts::blockchain::wallet           _wallet;
      fc::future<void>                  sim_loop_complete;
      fc::future<void>                  chain_connect_loop_complete;
};

void print_help()
{
    std::cout<<"Commands:\n";
    std::cout<<" quit\n";
    std::cout<<" importkey PRIV_KEY\n";
    std::cout<<" balance  -  print the wallet balances\n";
    std::cout<<" newaddr  -  print a new wallet address\n";
	std::cout<<" listaddr  - print the wallet address(es)\n";
    std::cout<<" transfer AMOUNT UNIT to ADDRESS  \n";
    std::cout<<" buy AMOUNT UNIT \n";
    std::cout<<" sell AMOUNT UNIT  \n";
    std::cout<<" short AMOUNT UNIT \n";
    std::cout<<" cover AMOUNT UNIT  \n";
    std::cout<<" add margin AMOUNT bts to UNIT  \n";
    std::cout<<" cancel ID IDX  \n";
    std::cout<<" html FILE\n";
    std::cout<<" json FILE\n";
    std::cout<<" market QUOTE BASE  \n";
    std::cout<<" show orders QUOTE BASE  \n";
}

void process_commands( fc::thread* main_thread, std::shared_ptr<client> c )
{
   try {
      std::string line;
#ifndef WIN32
      char* line_read = nullptr;
      line_read = readline(">>> ");
      if(line_read && *line_read)
          add_history(line_read);
      if( line_read == nullptr ) 
         return;
      line = line_read;
      free(line_read);
#else
      std::cout<<">>> ";
      std::getline( std::cin, line );
#endif ///WIN32
      while( std::cin.good() )
      {
         try {
         std::stringstream ss(line);
         std::string command;
         ss >> command;
   
         if( command == "h" || command == "help" )
         {
            print_help();
         }
         else if( command == "html" )
         {
            std::string file;
            ss >> file;
            main_thread->async( [=](){ c->dump_chain_html(file); } ).wait();
         }
         else if( command == "importkey" )
         {
            std::string key;
            ss >> key;
            std::string rescan;
            ss >> rescan;

            main_thread->async( [=]() { 
               c->_wallet.import_key( fc::ecc::private_key::regenerate( fc::sha256( key ) ) );
               if( rescan == "rescan" )
               {
                  std::cout<<"rescanning chain...\n";
                  c->_wallet.scan_chain(c->chain);
               }
               std::cout<<"import complete\n";
               c->print_balances(); 
            } ).wait();
         }
         else if( command == "json" )
         {
            std::string file;
            ss >> file;
            main_thread->async( [=](){ c->dump_chain_json(file); } ).wait();
         }
         else if( command == "c" || command == "cancel" )
         {
            std::string id;
            uint32_t idx;
            ss >> id >> idx;
            main_thread->async( [=](){ c->cancel_open_bid(id,idx); } ).wait();
         }
         else if( command == "q" || command == "quit" )
         {
            main_thread->async( [=](){ c->_wallet.save();} ).wait();
            return;
         }
         else if( command == "b" || command == "balance" )
         { 
            main_thread->async( [=](){ c->print_balances(); } ).wait();
         }
         else if( command == "l" || command == "listaddr"  )
         {
            main_thread->async( [=](){ c->print_wallet_address(); } ).wait();
         }
		 else if( command == "n" || command == "newaddr"  )
		 {
			 main_thread->async( [=](){ c->print_new_address(); } ).wait();
		 }
         else if( command == "t" || command == "transfer" )
         {
            double amount;
            std::string unit;
            std::string to;
            std::string addr;
            ss >> amount >> unit >> to >> addr;
            main_thread->async( [=](){ c->transfer(amount,unit,addr); } ).wait();
         }
         else if( command == "buy" )
         {
            std::string base_str,at;
            double      amount;
            double      quote_price;
            ss >> amount >> base_str;
            asset::type base_unit = fc::variant(base_str).as<asset::type>();
            asset       amnt = asset(amount,base_unit);

            std::cout<< "price per "<<base_str<<" (ie: 1 usd): ";
            std::getline( std::cin, line );
            std::stringstream pline(line);
            std::string quote_str;
            pline >> quote_price >> quote_str;
            asset::type quote_unit = fc::variant(quote_str).as<asset::type>();

            bts::blockchain::price pr =  asset( quote_price, quote_unit ) / asset( 1.0, base_unit );
            auto required_input = amnt * pr;
            auto curr_bal = main_thread->async( [=](){ return c->get_balance(required_input.unit); } ).wait();

            std::cout<<"current balance: "<< to_balance( curr_bal.amount.high_bits() ) <<" "<<fc::variant(required_input.unit).as_string()<<"\n"; 
            std::cout<<"total price: "<< to_balance(required_input.amount.high_bits()) <<" "<<fc::variant(required_input.unit).as_string()<<"\n"; 

            if( required_input > curr_bal )
            {
                std::cout<<"Insufficient Funds\n";
            }
            else
            {
                std::cout<<"submit order? (y|n): ";
                std::getline( std::cin, line );
                if( line == "yes" || line == "y" )
                {
                    main_thread->async( [=](){ c->buy(required_input,pr); } ).wait();
                    std::cout<<"order submitted\n";
                }
                else
                {
                    std::cout<<"order canceled\n";
                }
            }
         }
         else if( command == "sell" )
         {
            std::string base_unit_str;
            double      base_amount;
            ss >> base_amount >> base_unit_str;
            asset::type base_unit = fc::variant(base_unit_str).as<asset::type>();
            asset       base_amnt = asset(base_amount,base_unit);

            auto cur_bal = main_thread->async( [=](){ return c->get_balance(base_unit); } ).wait();
            std::cout<<"current balance: "<< std::string(cur_bal) <<"\n"; //to_balance( cur_bal.amount.high_bits() ) <<" "<<unit_str<<"\n"; 
            if( cur_bal < base_amnt )
            {
                std::cout<<"Insufficient Funds\n";
            }
            else
            {
               // TODO: get current bid/ask for all other assets as reference points

               std::cout<< "price per "<<base_unit_str<<" (ie: 1 usd): ";
               std::getline( std::cin, line );
               std::stringstream pline(line);
               double   quote_price;
               std::string quote_unit_str;
               pline >> quote_price >> quote_unit_str;

               asset::type quote_unit = fc::variant(quote_unit_str).as<asset::type>();

               auto quote_asset = asset( quote_price, quote_unit ) / asset( 1.0, base_unit );

               if( quote_unit == base_unit )
               {
                  std::cout<<"Attempt to sell for same asset\n";
               }
               else
               {
                  std::cout<<"Expected Proceeds: "<< std::string( base_amnt*quote_asset) <<"\n";//to_balance( (amnt*quote_price).amount.high_bits() ) <<" "<<quote_unit_str<<"\n";
                  std::cout<<"submit order? (y|n): ";
                  std::getline( std::cin, line );
                  if( line == "yes" || line == "y" )
                  {
                      main_thread->async( [=](){ c->sell(base_amnt,quote_asset); } ).wait();
                      std::cout<<"order submitted\n";
                  }
                  else
                  {
                      std::cout<<"order canceled\n";
                  }
               }
            }
         }
         else if( command == "short" )
         {
            std::string quote_unit_str;
            double      quote_amount;
            ss >> quote_amount >> quote_unit_str;
            asset::type quote_unit = fc::variant(quote_unit_str).as<asset::type>();
            asset       quote_amnt = asset(quote_amount,quote_unit);

            std::cout<< "price ("<<quote_unit_str<<"/bts): ";
            std::getline( std::cin, line );
            std::stringstream pline(line);
            double   quote_price;
            pline >> quote_price;
            bts::blockchain::price short_price = asset( quote_price, quote_unit ) / asset( 1.0, asset::bts ); //( priced, unit, asset::bts ); //asset::bts, unit );
            auto required_input = quote_amnt * short_price;

            std::cout<<"current balance: "<<  std::string(main_thread->async( [=](){ return c->get_balance(asset::bts); } ).wait())<<"\n"; 
            std::cout<<"required collateral: "<< std::string(required_input) <<"\n"; 
            std::cout<<"submit order? (y|n): ";
            std::getline( std::cin, line );
            if( line == "yes" || line == "y" )
            {
                main_thread->async( [=](){ c->short_sell(quote_amnt,short_price); } ).wait();
                std::cout<<"order submitted\n";
            }
            else
            {
                std::cout<<"order canceled\n";
            }
         }
         else if( command == "cover" )
         {
            double amount;
            std::string unit;
            ss >> amount >> unit;
            main_thread->async( [=](){ c->cover(amount,unit); } ).wait();
         }
         else if( command == "market" )
         {
            std::string quote_unit;
            std::string base_unit;
            ss >> quote_unit >> base_unit;
            main_thread->async( [=](){ c->print_market(quote_unit,base_unit); } ).wait();
         }
         else if( command == "add" )
         {
         }
         else if( command == "show" )
         {
         }
         else if( command != "" )
         {
            print_help();
         }
         } 
         catch( const fc::exception& e) 
         {
             std::cerr<<e.to_detail_string()<<"\n";
         }
#ifndef WIN32
         line_read = nullptr;
         line_read = readline(">>> ");
         if(line_read && *line_read)
             add_history(line_read);
         if( line_read == nullptr ) 
            return;
         line = line_read;
         free(line_read);
#else
         std::cout<<">>> ";
         std::getline( std::cin, line );
#endif ///WIN32
      }
   } 
   catch ( const fc::exception& e )
   {
      std::cerr<< e.to_detail_string() <<"\n";
      exit(1);
   }
}


int main( int argc, char** argv )
{ 
   auto main_thread = &fc::thread::current();

   std::cout<<"================================================================\n";
   std::cout<<"=                                                              =\n";
   std::cout<<"=             Welcome to BitShares X - Alpha                   =\n";
   std::cout<<"=                                                              =\n";
   std::cout<<"=  This software is in alpha testing and is not suitable for   =\n";
   std::cout<<"=  real monetary transactions or trading.  Use at your own     =\n";
   std::cout<<"=  risk.                                                       =\n";
   std::cout<<"=                                                              =\n";
   std::cout<<"=  Type 'help' for usage information.                          =\n";
   std::cout<<"================================================================\n";

   fc::file_appender::config ac;
   ac.filename = "log.txt";
   ac.truncate = false;
   ac.flush    = true;
   fc::logging_config cfg;

   cfg.appenders.push_back(fc::appender_config( "default", "file", fc::variant(ac)));

   fc::logger_config dlc;
   dlc.level = fc::log_level::debug;
   dlc.name = "default";
   dlc.appenders.push_back("default");
   cfg.loggers.push_back(dlc);
   fc::configure_logging( cfg );

   try {
     auto  bts_client = std::make_shared<client>();
     if( argc == 1 )
     bts_client->open( "datadir" );
     else if( argc == 2 )
     {
        bts_client->open( argv[1] );
     }
     else
     {
        std::cerr<<"Usage: "<<argv[0]<<" [DATADIR]\n";
        return -2;
     }
     bts_client->start_rpc_server(5678);

     
     fc::thread  read_thread;
     read_thread.async( [=](){ process_commands( main_thread, bts_client ); } ).wait();
   } 
   catch ( const fc::exception& e )
   {
      std::cerr<< e.to_string() << "\n";
      return -1;
   }
   return 0;
}
