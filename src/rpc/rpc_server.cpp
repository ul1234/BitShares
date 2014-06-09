#include <bts/rpc/rpc_server.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/network/tcp_socket.hpp>
#include <fc/rpc/json_connection.hpp>
#include <fc/thread/thread.hpp>
#include <bts/application.hpp>

using namespace fc;

namespace bts { namespace rpc { 

  namespace detail 
  {
    class server_impl
    {
       public:
         server::config      _config;
         bitname::client_ptr _bitnamec;

         fc::tcp_server      _tcp_serv;

         fc::future<void>    _accept_loop_complete;

         /** the set of connections that have successfully logged in */
         std::unordered_set<fc::rpc::json_connection*> _login_set;


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
                //exit(1);
              }

              auto buf_istream = std::make_shared<fc::buffered_istream>( sock );
              auto buf_ostream = std::make_shared<fc::buffered_ostream>( sock );

              auto json_con = std::make_shared<fc::rpc::json_connection>( std::move(buf_istream), std::move(buf_ostream) );
              register_methods( json_con );

         //   TODO  0.5 BTC: handle connection errors and and connection closed without
         //   creating an entirely new context... this is waistful
         //     json_con->exec(); 
              fc::async( [json_con]{ json_con->exec().wait(); } );
         //     _connections.push_back( std::move( json_con ) );
           }
         }

         void register_methods( const fc::rpc::json_connection_ptr& con )
         {
            ilog( "login!" );
            // don't capture the shared ptr, it would create a circular reference
            fc::rpc::json_connection* capture_con = con.get(); 
            con->add_method( "login", [=]( const fc::variants& params ) -> fc::variant 
            {
                FC_ASSERT( params.size() == 2 );
                FC_ASSERT( params[0].as_string() == _config.user )
                FC_ASSERT( params[1].as_string() == _config.pass )
                _login_set.insert( capture_con );
                return fc::variant( true );
            });
            if( _bitnamec ) 
            {
               register_bitname_methods( con );
            }
         }

         void check_login( fc::rpc::json_connection* con )
         {
            if( _login_set.find( con ) == _login_set.end() )
            {
               FC_THROW_EXCEPTION( exception, "not logged in" ); 
            }
         }

         void register_bitname_methods( const fc::rpc::json_connection_ptr& con )
         {
            // don't capture the shared ptr, it would create a circular reference
            fc::rpc::json_connection* capture_con = con.get(); 
            con->add_method( "lookup_name", [=]( const fc::variants& params ) -> fc::variant 
            {
                FC_ASSERT( params.size() == 1 );
           //     check_login( capture_con );
                return fc::variant( _bitnamec->lookup_name( params[0].as_string() ) );
            });

            con->add_method( "reverse_name_lookup", [=]( const fc::variants& params ) -> fc::variant 
            {
                FC_ASSERT( params.size() == 1 );
                check_login( capture_con );
                return fc::variant( _bitnamec->reverse_name_lookup( params[0].as<fc::ecc::public_key>() ) );
            });

            /**
             *  params : ["sha256 digest hex","ecc compact signature hex"]
             *  result : "ECC PUBLIC KEY"
             */
            con->add_method( "verify_signature", [=]( const fc::variants& params ) -> fc::variant 
            {
                FC_ASSERT( params.size() == 2 );
                std::string message = "SIGNED BY SANCHO " + params[0].as_string();
                auto digest = fc::sha256::hash(message.c_str(), message.size() );
                return fc::variant( fc::ecc::public_key( params[1].as<fc::ecc::compact_signature>(), digest ) );
            });

            /**
             *  params : ["name","SHA256 Digest Hex"]
             *  result : "ecc compact signature" of sha256( "SIGNED BY SANCHO " + "SHA256 Digest Hex" )
             *
             *  @note "SANCHO_SIGNED" is meant to prevent this from being used to sign data not intended to
             *  be verifyed by verify_signature.
             */
            con->add_method( "sign_message", [=]( const fc::variants& params ) -> fc::variant 
            {
                FC_ASSERT( params.size() == 2 );
                check_login( capture_con );
                auto current_profile = bts::application::instance()->get_profile();
                FC_ASSERT( current_profile );

                auto keys = current_profile->get_keychain();

                fc::ecc::private_key account_priv_key = keys.get_identity_key( params[0].as_string() );
                std::string message = "SIGNED BY SANCHO " + params[1].as_string();
                auto digest = fc::sha256::hash(message.c_str(), message.size() );

                auto sig = account_priv_key.sign( digest );

                return fc::variant( sig );
            });

            /**
             *   params : ["profile_name","profile_password"]
             */
            con->add_method( "load_profile", [=]( const fc::variants& params ) -> fc::variant 
            {
                FC_ASSERT( params.size() == 2 );
                check_login( capture_con );
                bts::application::instance()->load_profile( params[0].as_string(), params[1].as_string() );
                return fc::variant();
            });

            /**
             *  params : ["name", effort[0-1.0] ]
             */
            con->add_method( "mine_name", [=]( const fc::variants& params ) -> fc::variant 
            {
                FC_ASSERT( params.size() == 2 );
                check_login( capture_con );
                auto current_profile = bts::application::instance()->get_profile();
                FC_ASSERT( current_profile );


                std::string name = params[0].as_string();
                float effort     = params[1].as<float>();
                // TODO: use effort

                auto keys = current_profile->get_keychain();
                auto priv_key = keys.get_identity_key( name );

                if( effort > 0 ) 
                {
                    _bitnamec->mine_name( name, priv_key.get_public_key() );
                }
                else
                {
                    _bitnamec->stop_mining_name( name );
                }
                return fc::variant();
            });

            /**
             *  params : ["IP:PORT","IP:PORT",...]
             */
            con->add_method( "add_nodes", [=]( const fc::variants& params ) -> fc::variant 
            {
                check_login( capture_con );
                ilog( "add_nodes ${params}", ("params",params) );
                auto app = bts::application::instance();
                auto net = app->get_network();
                for( auto itr = params.begin(); itr != params.end(); ++itr )
                {
                    auto ep = fc::ip::endpoint::from_string( itr->as_string() );
                    ilog( "connect to ${ep}", ("ep",ep) );
                    net->connect_to(ep);
                }
                return fc::variant();
            });

            /**
             *  params : []
             *  result : [ "IP:PORT", "IP:PORT", ...] 
             */
            con->add_method( "get_connections", [=]( const fc::variants& params ) -> fc::variant 
            {
                check_login( capture_con );
                auto app = bts::application::instance();
                auto net = app->get_network();
                auto cons = net->get_connections();
                std::vector<std::string> endpoints;
                endpoints.reserve(cons.size());
                for( auto itr = cons.begin(); itr != cons.end(); ++itr )
                {
                  endpoints.push_back( std::string( (*itr)->remote_endpoint() ) ); 
                }
                return fc::variant(endpoints);
            });

         }
    };
  } // detail

  server::server()
  :my( new detail::server_impl() )
  {
  }

  server::~server()
  { 
     try {
         my->_tcp_serv.close();
         if( my->_accept_loop_complete.valid() )
         {
            my->_accept_loop_complete.cancel();
            my->_accept_loop_complete.wait();
         }
     } 
     catch ( const fc::canceled_exception& e ){}
     catch ( const fc::exception& e )
     {
        wlog( "unhandled exception thrown in destructor.\n${e}", ("e", e.to_detail_string() ) );
     }
  }

  void server::configure( const server::config& cfg )
  {
     try {
      // FC_ASSERT( cfg.port != 0 );
       my->_config = cfg;
       ilog( "listening for rpc connections on port ${port}", ("port",cfg.port) );
       my->_tcp_serv.listen( cfg.port );
       ilog( "listening for rpc connections on port ${port}", ("port",my->_tcp_serv.get_port()) );
     // TODO shutdown server if already configured prior to restarting it
     
       my->_accept_loop_complete = fc::async( [=]{ my->accept_loop(); } );
     
     } FC_RETHROW_EXCEPTIONS( warn, "attempting to configure rpc server ${port}", ("port",cfg.port)("config",cfg) );
  }

  void server::set_bitname_client( const bts::bitname::client_ptr& bitnamec )
  {
     my->_bitnamec = bitnamec;
  }




} } // bts::rpc
