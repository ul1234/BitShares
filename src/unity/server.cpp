#include <unity/server.hpp>
#include <unity/connection.hpp>
#include <unity/messages.hpp>

#include <fc/reflect/reflect.hpp>
#include <mail/message.hpp>
#include <mail/stcp_socket.hpp>
#include <bts/db/level_map.hpp>
#include <fc/time.hpp>
#include <fc/network/tcp_socket.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/thread/thread.hpp>
#include <fc/thread/future.hpp>
#include <fc/io/raw.hpp>
#include <fc/log/logger.hpp>

#include <iostream>

#include <algorithm>
#include <unordered_map>
#include <map>

namespace unity 
{
   namespace detail 
   {
      class server_impl : public connection_delegate
      {
          public:
             server::config                                        _config;
                                                                  
             fc::tcp_server                                        _tcp_serv;
             fc::future<void>                                      _accept_loop_complete;
             std::unordered_map<fc::ip::endpoint,connection_ptr>   _connections;

             void close()
             {
                 ilog( "closing connections..." );
                 try 
                 {
                     _tcp_serv.close();
                     if( _accept_loop_complete.valid() )
                     {
                         _accept_loop_complete.cancel();
                         _accept_loop_complete.wait();
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
                   ilog( "accepted connection from ${ep}", 
                         ("ep", std::string(s->get_socket().remote_endpoint()) ) );
                   
                   auto con = std::make_shared<connection>(s,this);
                   _connections[con->remote_endpoint()] = con;
                   //if( ser_del ) ser_del->on_connected( con );
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
                  if( m.type == message_type::subscribe_msg )
                  {
                     auto sm = m.as<subscribe_message>();
                     ilog( "recv: ${m}", ("m",sm) );
                     // verify c is on the unique node list, if c is already connected
                     // then close the connection.
                  }
                  else if( m.type == message_type::blob_msg )
                  {
                     auto blob = m.as<blob_message>();
                     ilog( "recv: ${m}", ("m",blob) );

                     // if this is a new message for us, broadcast it to all
                     // connections... else drop it

                     // if output proposal message changed... broadcast it
                  }
                  else if( m.type == message_type::proposal_msg )
                  {
                     auto prop = m.as<proposal_message>();
                     ilog( "recv: ${m}", ("m",prop) );
                     // process proposal...

                     // if output proposal message changed... broadcast it
                  }
             }
             virtual void on_connection_disconnected( connection& c )
             {
               try {
                 ilog( "cleaning up connection after disconnect ${e}", ("e", c.remote_endpoint()) );
                 auto cptr = c.shared_from_this();
                 FC_ASSERT( cptr );
                 //if( ser_del ) ser_del->on_disconnected( cptr );
                 auto itr = _connections.find(c.remote_endpoint());
                 _connections.erase( itr ); //c.remote_endpoint() );
                 // we cannot close/delete the connection from this callback or we will hang the fiber
                 fc::async( [cptr]() {} );
               } FC_RETHROW_EXCEPTIONS( warn, "error thrown handling disconnect" );
             }

             /**
              *  This method is called async 
              */
             void accept_loop() throw()
             {
                try
                {
                   while( !_accept_loop_complete.canceled() )
                   {
                      stcp_socket_ptr sock = std::make_shared<stcp_socket>();
                      _tcp_serv.accept( sock->get_socket() );
             
                      // do the acceptance process async
                      fc::async( [=](){ accept_connection( sock ); } );
             
                      // limit the rate at which we accept connections to prevent
                      // DOS attacks.
                      fc::usleep( fc::microseconds( 1000*1 ) );
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
   } // namespace detail


server::server()
:my( new detail::server_impl() )
{
}

server::~server()
{
   my->close();
}

void server::configure( const server::config& cfg )
{ try {
    my->_config = cfg;
    my->_tcp_serv.listen( cfg.unity_port );
    my->_accept_loop_complete = fc::async( [=](){ my->accept_loop(); } );
} FC_RETHROW_EXCEPTIONS( warn, "", ("config",cfg) ) }

} // namespace untiy
