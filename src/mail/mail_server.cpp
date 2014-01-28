#include <mail/mail_server.hpp>
#include <mail/mail_connection.hpp>
#include <mail/message.hpp>
#include <mail/stcp_socket.hpp>
#include <bts/db/level_map.hpp>
#include <bts/bitchat/bitchat_private_message.hpp>
#include <bts/bitchat/bitchat_messages.hpp>
#include <fc/time.hpp>
#include <fc/network/tcp_socket.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/thread/thread.hpp>
#include <fc/thread/future.hpp>
#include <fc/io/raw.hpp>
#include <fc/log/logger.hpp>


#include <algorithm>
#include <unordered_map>
#include <map>

namespace mail {

  namespace detail
  {
     class server_impl : public connection_delegate
     {
        public:
          server_impl()
          :ser_del(nullptr)
          {}

          ~server_impl()
          {
             close();
          }
          void close()
          {
              ilog( "closing connections..." );
              try 
              {
                  for( auto i = pending_connections.begin(); i != pending_connections.end(); ++i )
                  {
                    (*i)->close();
                  }
                  tcp_serv.close();
                  if( accept_loop_complete.valid() )
                  {
                      accept_loop_complete.cancel();
                      accept_loop_complete.wait();
                  }
              } 
              catch ( const fc::canceled_exception& e )
              {
                  ilog( "expected exception on closing tcp server\n" );  
              }
              catch ( const fc::exception& e )
              {
                  wlog( "unhandled exception in destructor ${e}", ("e", e.to_detail_string() ));
              } 
              catch ( ... )
              {
                  elog( "unexpected exception" );
              }
          }
          server_delegate*                                            ser_del;
          fc::ip::address                                             _external_ip;

          bts::db::level_map<fc::time_point,bts::bitchat::encrypted_message>    _message_db;

          std::unordered_map<fc::ip::endpoint,connection_ptr>         connections;

          std::set<connection_ptr>                                    pending_connections;
          server::config                                              cfg;
          fc::tcp_server                                              tcp_serv;
                                                                     
          fc::future<void>                                            accept_loop_complete;
                                                                     
          /**
           *  This is called every time a message is received from c, there are only two
           *  messages supported:  seek to time and broadcast.  When a message is 
           *  received it goes into the database which all of the connections are 
           *  reading from and sending to their clients.
           *
           *  The difficulty required adjusts every 5 minutes with the goal of maintaining
           *  an average data rate of 1.5 kb/sec from all connections.
           */
          virtual void on_connection_message( connection& c, const message& m )
          {
               // TODO: perhaps do this ASYNC?
               // itr->second->handle_message( c.shared_from_this(), m );
               if( m.type == bts::bitchat::encrypted_message::type )
               {
                   auto pm = m.as<bts::bitchat::encrypted_message>();
                   wlog( "received message size: ${s}", ("s",m.size) );
                   //ilog( "received ${m}", ( "m",pm) );
             
            //       if( pm.validate_proof() )
                   if( m.size < 1024*1024*2 ) // 2 MB limit...
                   {
                      _message_db.store( fc::time_point::now(), pm );
                   }
               }
               else if( m.type == bts::bitchat::client_info_message::type )
               {
                   auto ci = m.as<bts::bitchat::client_info_message>();
                   ilog( "sync from time ${t}  server time ${st}", ("t", ci.sync_time )("st",fc::time_point::now()) );
                   c.set_last_sync_time( ci.sync_time );
                   if( c.get_last_sync_time() != fc::time_point() )
                   {
                      c.exec_sync_loop();
                   }
               }
               else
               {
                   c.close();
               }
          }


          virtual void on_connection_disconnected( connection& c )
          {
            try {
              ilog( "cleaning up connection after disconnect ${e} remaining connections ${c}", ("e", c.remote_endpoint())("c",connections.size()-1) );
              auto cptr = c.shared_from_this();
              FC_ASSERT( cptr );
              if( ser_del ) ser_del->on_disconnected( cptr );
              auto itr = connections.find(c.remote_endpoint());
              connections.erase( itr ); //c.remote_endpoint() );

              // delete this later... capture it, if we do not do this it will hang
              fc::async( [cptr](){} );
            } FC_RETHROW_EXCEPTIONS( warn, "error thrown handling disconnect" );
          }

          /**
           *  This method is called via async from accept_loop and
           *  should not throw any exceptions because they are not
           *  being caught anywhere.
           *
           *  
           */
          void accept_connection( const stcp_socket_ptr& s )
          {
             try 
             {
                // init DH handshake, TODO: this could yield.. what happens if we exit here before
                // adding s to connections list.
                s->accept();
                
                auto con = std::make_shared<connection>(s,this);
                con->set_database(&_message_db);
                connections[con->remote_endpoint()] = con;
                ilog( "accepted connection from ${ep}  total connections ${c}", 
                      ("ep", std::string(s->get_socket().remote_endpoint()) )("c",connections.size()) );
                if( ser_del ) ser_del->on_connected( con );
             } 
             catch ( const fc::canceled_exception& e )
             {
                ilog( "canceled accept operation" );
             }
             catch ( const fc::exception& e )
             {
                wlog( "error accepting connection: ${e}", ("e", e.to_detail_string() ) );
             }
             catch( ... )
             {
                elog( "unexpected exception" );
             }
          }

          /**
           *  This method is called async 
           */
          void accept_loop() throw()
          {
             try
             {
                while( !accept_loop_complete.canceled() )
                {
                   stcp_socket_ptr sock = std::make_shared<stcp_socket>();
                   tcp_serv.accept( sock->get_socket() );
                   ilog( "accept" );

                   // do the acceptance process async
                   fc::async( [=](){ accept_connection( sock ); } );

                   // limit the rate at which we accept connections to prevent
                   // DOS attacks.
                   fc::usleep( fc::microseconds( 1000*10 ) );
                }
             } 
             catch ( fc::eof_exception& e )
             {
                ilog( "accept loop eof" );
             }
             catch ( fc::canceled_exception& e )
             {
                ilog( "accept loop canceled" );
             }
             catch ( fc::exception& e )
             {
                elog( "tcp server socket threw exception\n ${e}", 
                                     ("e", e.to_detail_string() ) );
                // TODO: notify the server delegate of the error.
             }
             catch( ... )
             {
                elog( "unexpected exception" );
             }
          }
     };
  }




  server::server()
  :my( new detail::server_impl() ){}

  server::~server()
  { }


  void server::set_delegate( server_delegate* sd )
  {
     my->ser_del = sd;
  }

  void server::configure( const server::config& c )
  {
    try {
      my->cfg = c;

      ilog( "listening for stcp connections on port ${p}", ("p",c.port) );
      my->tcp_serv.listen( c.port );
      my->accept_loop_complete = fc::async( [=](){ my->accept_loop(); } ); 
      my->_message_db.open( "message_db" );

    } FC_RETHROW_EXCEPTIONS( warn, "error configuring server", ("config", c) );
  }

  std::vector<connection_ptr> server::get_connections()const
  { 
      std::vector<connection_ptr>  cons; 
      cons.reserve( my->connections.size() );
      for( auto itr = my->connections.begin(); itr != my->connections.end(); ++itr )
      {
        cons.push_back(itr->second);
      }
      return cons;
  }

  /*
  void server::broadcast( const message& m )
  {
      for( auto itr = my->connections.begin(); itr != my->connections.end(); ++itr )
      {
        try {
           itr->second->send(m);
        } 
        catch ( const fc::exception& e ) 
        {
           // TODO: propagate this exception back via the delegate or some other means... don't just fail
           wlog( "exception thrown while broadcasting ${e}", ("e", e.to_detail_string() ) );
        }
      }
  }
  */

  void server::close()
  {
    try {
      my->close();
    } FC_RETHROW_EXCEPTIONS( warn, "error closing server socket" );
  }

} // namespace mail
