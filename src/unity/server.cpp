#include <unity/messages.hpp>
#include <unity/server.hpp>
#include <unity/connection.hpp>
#include <unity/node.hpp>
#include <fc/crypto/sha256.hpp>

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
             unity::node                                           _node;                                                     
             fc::tcp_server                                        _tcp_serv;
             fc::future<void>                                      _accept_loop_complete;
             fc::future<void>                                      _connect_loop_complete;
             std::unordered_map<fc::ip::endpoint,connection_ptr>   _connections;
             std::unordered_map<fc::ripemd160, std::vector<char> > _unconfirmed_blobs;
             std::unordered_set<fc::ripemd160>                     _confirmed_blobs;

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
             bool is_authorized_node( const bts::address& adr )
             {
                for( auto itr = _config.hosts.begin(); itr != _config.hosts.end(); ++itr )
                {
                   if( itr->first == adr ) return true;
                }
                return false;
             }

             void broadcast( const mail::message& msg )
             {
                auto cons_copy = _connections;
                fc::async( [cons_copy,msg]()
                {
                   for( auto itr = cons_copy.begin(); itr != cons_copy.end(); ++itr )
                   {
                      try {
                         itr->second->send( msg );
                      } catch ( ... ) {}
                   }
                } ).wait();
             }

             void add_blob( std::vector<char> blob )
             {
                 FC_ASSERT( blob.size() > 0 );
                 auto id = fc::ripemd160::hash( blob.data(), blob.size() );

                 if( !is_unconfirmed_blob( id ) )
                 {
                    if( is_confirmed_blob(id) ) return;
                    _unconfirmed_blobs[id] = blob;
                    _node.set_item_validity( id, true );


                    auto cur = _node.get_current_proposal();
                    if( cur.items.size() > 0 ) 
                    {
                       ilog( "broadcast counter proposal ${p}", ("p",cur) );
                       broadcast( mail::message( proposal_message( cur ) ) );
                    }


                    // TODO: only broadcast to nodes that don't have this blob...
                      auto cons_copy = _connections;
                      fc::async( [cons_copy,blob,id]()
                      { 
                         auto  msg = mail::message( blob_message( blob ) );
                         for( auto itr = cons_copy.begin(); itr != cons_copy.end(); ++itr )
                         {
                            try {
                               if( !itr->second->knows_blob(id) )
                               {
                                  itr->second->send( msg  );
                               }
                            } catch ( ... ) {}
                         }
                      } ).wait();
                 }
             }

             bool is_confirmed_blob( const fc::ripemd160& id )
             {
                 return _confirmed_blobs.find(id) != _confirmed_blobs.end();
             }

             bool is_unconfirmed_blob( const fc::ripemd160& id )
             {
                 return _unconfirmed_blobs.find(id) != _unconfirmed_blobs.end();
             }

             bool is_new_blob( const fc::ripemd160& id )
             {
                 if( is_confirmed_blob(id)   ) return false;
                 if( is_unconfirmed_blob(id) ) return false;
                 return true;
             }

             void connect_loop()
             {
                 while( !_connect_loop_complete.canceled() )
                 {
                    for( auto itr = _config.hosts.begin(); itr != _config.hosts.end(); ++itr )
                    {
                        if( !is_connected( itr->first ) && itr->second != std::string() )
                        {
                           try {
                              auto con = std::make_shared<unity::connection>(this);
                              con->connect( itr->second );
                              on_new_connection( con );
                           } 
                           catch ( const fc::exception& e )
                           {
                              wlog( "${warn}", ( "warn", e.to_detail_string() ) );
                           }
                        }
                    }
                    fc::usleep( fc::seconds(60) );
                 }
             }

             bool is_connected( const bts::address& unique_node )
             {
                auto cons = _connections;
                for( auto itr = cons.begin(); itr != cons.end(); ++itr )
                {
                   if( itr->second->get_remote_id() == unique_node )
                      return true;
                }
                return false;
             } // is_connected

             void on_new_connection( const connection_ptr& con )
             {
                 _connections[con->remote_endpoint()] = con;
                 ilog( "connected to ${ep}" , ( "ep",con->remote_endpoint() ) );

                 subscribe_message msg;
                 msg.version = 0;
                 msg.timestamp = fc::time_point::now();
                 msg.sign( _config.node_config.node_key );
                 con->send( message( msg ) );
                 //if( ser_del ) ser_del->on_connected( con );
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
                   on_new_connection( con );
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
             } // accept_connection


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
                     auto node_id = bts::address(sm.signee());
                     ilog( "remote id: ${id}", ("id", node_id ) );
                     // verify c is on the unique node list, if c is already connected
                     // then close the connection.
                     if( !is_authorized_node( node_id ) )
                     {
                        wlog( "${id} is not in the unique node list", ("id",node_id) );
                        c.close();
                     }
                     c.set_remote_id( node_id );
                  }
                  else if( m.type == message_type::blob_msg )
                  {
                     auto blob = m.as<blob_message>();
                     FC_ASSERT( c.get_remote_id() != bts::address() );
                     auto blob_id = fc::ripemd160::hash( blob.blob.data(), blob.blob.size() );
                     ilog( "recv blob: ${m} size: ${s}", ("m",blob_id)("s",blob.blob.size()) );
                     c.set_knows_blob( blob_id );
                     add_blob( blob.blob );
                     // if this is a new message for us, broadcast it to all
                     // connections... else drop it

                     // if output proposal message changed... broadcast it
                  }
                  else if( m.type == message_type::proposal_msg )
                  {
                     FC_ASSERT( c.get_remote_id() != bts::address() );
                     auto prop = m.as<proposal_message>();
                     ilog( "recv: ${m}", ("m",prop) );
                     handle_proposal( c, prop.signed_prop );
                     // if output proposal message changed... broadcast it
                  }
                  else
                  {
                     wlog( "unknown message type ${m}", ("m",m.type) );
                     c.close();
                  }
             }
             void handle_proposal( connection& c, const signed_proposal& p )
             {
                 ilog( "handle proposal ${p}", ("p",p) );
                 if( _node.process_proposal( p ) )
                 {
                    auto cur = _node.get_current_proposal();
                    ilog( "broadcast counter proposal ${p}", ("p",cur) );
                    broadcast( mail::message( proposal_message( cur ) ) );
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
    
    auto node_cfg = cfg.node_config;
    for( auto itr = cfg.hosts.begin(); itr != cfg.hosts.end(); ++itr )
    {
       node_cfg.unique_node_list.insert(itr->first);
    }
    my->_node.configure(node_cfg);


    my->_accept_loop_complete  = fc::async( [=](){ my->accept_loop();  } );
    my->_connect_loop_complete = fc::async( [=](){ my->connect_loop(); } );
} FC_RETHROW_EXCEPTIONS( warn, "", ("config",cfg) ) }

void server::add_blob( std::vector<char> blob )
{
    my->add_blob( std::move(blob) );
}



} // namespace untiy
