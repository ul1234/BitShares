#include <mail/mail_connection.hpp>
#include <mail/message.hpp>
#include <bts/config.hpp>

#include <fc/network/tcp_socket.hpp>
#include <fc/network/resolve.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/thread/thread.hpp>
#include <fc/io/raw.hpp>
#include <fc/log/logger.hpp>
#include <fc/string.hpp>
#include <fc/thread/mutex.hpp>
#include <fc/thread/scoped_lock.hpp>

#include <unordered_map>
#include <bts/db/level_map.hpp>
#include <bts/bitchat/bitchat_private_message.hpp>

namespace mail {

  namespace detail
  {
     class connection_impl
     {
        public:
          connection_impl(connection& s)
          :self(s),con_del(nullptr){}
          connection&          self;
          stcp_socket_ptr      sock;
          fc::ip::endpoint     remote_ep;
          connection_delegate* con_del;

          fc::time_point _sync_time;
          bts::db::level_map<fc::time_point,bts::bitchat::encrypted_message>*   _db;

          /** used to ensure that messages are written completely */
          fc::mutex              write_lock;


          fc::future<void>       read_loop_complete;
          fc::future<void>       exec_sync_loop_complete;
          fc::time_point         last_msg_time;

          void read_loop()
          {
            const int BUFFER_SIZE = 16;
            const int LEFTOVER = BUFFER_SIZE - sizeof(message_header);
            try {
               message m;
               while( true )
               {
                  char tmp[BUFFER_SIZE];
                  sock->read( tmp, BUFFER_SIZE );
                  memcpy( (char*)&m, tmp, sizeof(message_header) );
                  if(con_del->on_message_transmission_started(self, m) == false)
                    break;

                  m.data.resize( m.size + 16 ); //give extra 16 bytes to allow for padding added in send call
                  memcpy( (char*)m.data.data(), tmp + sizeof(message_header), LEFTOVER );
                  sock->read( m.data.data() + LEFTOVER, 16*((m.size -LEFTOVER + 15)/16) );

                  try { // message handling errors are warnings... 
                    con_del->on_connection_message( self, m );
                  } 
                  catch ( fc::canceled_exception& e ) { throw; }
                  catch ( fc::eof_exception& e ) { throw; }
                  catch ( fc::exception& e ) 
                  { 
                     wlog( "disconnected ${er}", ("er", e.to_detail_string() ) );
                     // TODO: log and potentiall disconnect... for now just warn.
                  }
               }
            } 
            catch ( const fc::canceled_exception& e )
            {
              if( con_del )
              {
                con_del->on_connection_disconnected( self );
              }
              else
              {
          //      wlog( "disconnected ${e}", ("e", e.to_detail_string() ) );
              }
            }
            catch ( const fc::eof_exception& e )
            {
              if( con_del )
              {
                con_del->on_connection_disconnected( self );
              }
              else
              {
                wlog( "disconnected ${e}", ("e", e.to_detail_string() ) );
              }
            }
            catch ( fc::exception& er )
            {
              if( con_del )
              {
                elog( "disconnected ${er}", ("er", er.to_detail_string() ) );
                con_del->on_connection_disconnected( self );
              }
              else
              {
                elog( "disconnected ${e}", ("e", er.to_detail_string() ) );
              }
              FC_RETHROW_EXCEPTION( er, warn, "disconnected ${e}", ("e", er.to_detail_string() ) );
            }
            catch ( ... )
            {
              // TODO: call con_del->????
              FC_THROW_EXCEPTION( unhandled_exception, "disconnected: {e}", ("e", fc::except_str() ) );
            }
          }
     };
  } // namespace detail

  connection::connection( const stcp_socket_ptr& c, connection_delegate* d )
  :my( new detail::connection_impl(*this) )
  {
    my->sock = c;
    my->con_del = d;
    my->remote_ep = remote_endpoint();
    my->read_loop_complete = fc::async( [=](){ my->read_loop(); } );
  }

  connection::connection( connection_delegate* d )
  :my( new detail::connection_impl(*this) ) 
  { 
    assert( d != nullptr );
    my->con_del = d; 
  }

  void connection::set_last_sync_time( const fc::time_point& sync_time )
  {
     my->_sync_time = sync_time;
  }
  fc::time_point connection::get_last_sync_time()const
  {
     return my->_sync_time;
  }

  connection::~connection()
  {
    try {
        // delegate does not get called from destructor...
        // because shared_from_this() will return nullptr 
        // and cause us all kinds of grief
        my->con_del = nullptr; 

        close();
        if( my->read_loop_complete.valid() )
        {
          my->read_loop_complete.wait();
        }
        if( my->exec_sync_loop_complete.valid() )
        {
          my->exec_sync_loop_complete.cancel();
          my->exec_sync_loop_complete.wait();
        }
    } 
    catch ( const fc::canceled_exception& e )
    {
      ilog( "canceled" );
    }
    catch ( const fc::exception& e )
    {
      wlog( "unhandled exception on close:\n${e}", ("e", e.to_detail_string()) );   
    }
    catch ( ... )
    {
      elog( "unhandled exception on close ${e}", ("e", fc::except_str()) );   
    }
  }
  stcp_socket_ptr connection::get_socket()const
  {
     return my->sock;
  }

  void connection::close()
  {
     try {
         if( my->sock )
         {
           my->sock->get_socket().close();
           if( my->read_loop_complete.valid() )
           {
              wlog( "waiting for socket to close" );
              my->read_loop_complete.wait();
              wlog( "socket closed" );
           }
         }
     } FC_RETHROW_EXCEPTIONS( warn, "exception thrown while closing socket" );
  }
  void connection::connect( const fc::ip::endpoint& ep )
  {
     try {
       // TODO: do we have to worry about multiple calls to connect?
       my->sock = std::make_shared<stcp_socket>();
       my->sock->connect_to(ep); 
       my->remote_ep = remote_endpoint();
       ilog( "    connected to ${ep}", ("ep", ep) );
       my->read_loop_complete = fc::async( [=](){ my->read_loop(); } );
     } FC_RETHROW_EXCEPTIONS( warn, "error connecting to ${ep}", ("ep",ep) );
  }

  void connection::connect( const std::string& host_port )
  {
      int idx = host_port.find( ':' );
      auto eps = fc::resolve( host_port.substr( 0, idx ), fc::to_int64(host_port.substr( idx+1 )));
      ilog( "connect to ${host_port} and resolved ${endpoints}", ("host_port", host_port)("endpoints",eps) );
      for( auto itr = eps.begin(); itr != eps.end(); ++itr )
      {
         try 
         {
            connect( *itr );
            return;
         } 
         catch ( const fc::exception& e )
         {
            wlog( "    attempt to connect to ${ep} failed.", ("ep", *itr) );
         }
      }
      FC_THROW_EXCEPTION( exception, "unable to connect to ${host_port}", ("host_port",host_port) );
  }

  void connection::send( const message& m )
  {
    try {
      fc::scoped_lock<fc::mutex> lock(my->write_lock);
      size_t len = MAIL_PACKED_MESSAGE_HEADER + m.size;
      len = 16*((len+15)/16); //pad the message we send to a multiple of 16 bytes
      std::vector<char> tmp(len);
      memcpy( tmp.data(), (char*)&m, MAIL_PACKED_MESSAGE_HEADER );
      memcpy( tmp.data() + MAIL_PACKED_MESSAGE_HEADER, m.data.data(), m.size );
      my->sock->write( tmp.data(), tmp.size() );
      my->sock->flush();
    } FC_RETHROW_EXCEPTIONS( warn, "unable to send message" );
  }


  fc::ip::endpoint connection::remote_endpoint()const 
  {
     if( get_socket()->get_socket().is_open() )
     {
         return my->remote_ep = get_socket()->get_socket().remote_endpoint();
     }
     // TODO: document why we are not throwing an exception if there is no remote endpoint?
     return my->remote_ep;
  }

  void connection::exec_sync_loop()
  {
      ilog( "exec sync loop" );
      my->exec_sync_loop_complete = fc::async( [=]() 
      {
        try {
         // ilog( "in exec sync loop" );
          while( !my->exec_sync_loop_complete.canceled() )
          {
             //ilog( "sync time ${t}", ("t",my->_sync_time) );
             auto itr = my->_db->lower_bound( my->_sync_time );
             if( !itr.valid() )
             {
              ilog( "no valid message found" );
             }
             while( itr.valid() && !my->exec_sync_loop_complete.canceled() )
             {
                if( itr.key() > my->_sync_time )
                {
                   send( message( itr.value() ) );
                   my->_sync_time = itr.key();
                }
                ++itr;
             }
             fc::usleep( fc::seconds(15) );
          }
        } 
        catch ( const fc::exception& e )
        {
           wlog( "${e}", ("e", e.to_detail_string() ) );
        }
        catch ( ... )
        {
           wlog("other exeception" );
        }
      });
  }

  void connection::set_database( bts::db::level_map<fc::time_point,bts::bitchat::encrypted_message>* db )
  {
     my->_db = db;
  }


} // mail
