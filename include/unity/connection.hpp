#pragma once
#include <mail/stcp_socket.hpp>
#include <mail/message.hpp>
#include <fc/exception/exception.hpp>
#include <unity/node.hpp>

using namespace mail;

namespace unity 
{
   namespace detail { class connection_impl; }

   class connection;
   typedef std::shared_ptr<connection> connection_ptr;

   /** 
    * @brief defines callback interface for connections
    */
   class connection_delegate
   {
      public:
        virtual ~connection_delegate(){}; 
        virtual void on_connection_message( connection& c, const message& m ){};
        virtual void on_connection_disconnected( connection& c ){}
   };

   /**
    *  Manages a connection to a remote p2p node. A connection
    *  processes a stream of messages that have a common header 
    *  and ensures everything is properly encrypted.
    *
    *  A connection also allows arbitrary data to be attached to it
    *  for use by other protocols built at higher levels.
    */
   class connection : public std::enable_shared_from_this<connection>
   {
      public:
        connection( const stcp_socket_ptr& c, connection_delegate* d);
        connection( connection_delegate* d );
        ~connection();
   
        stcp_socket_ptr  get_socket()const;
        fc::ip::endpoint remote_endpoint()const;
        id_type          get_remote_id()const;
        void             set_remote_id( const id_type& id );
        
        void send( const message& m );
   
        void connect( const std::string& host_port );  
        void connect( const fc::ip::endpoint& ep );
        void close();

      private:
        std::unique_ptr<detail::connection_impl> my;
   };

    
} // namespace unity
