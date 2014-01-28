#pragma once
#include <mail/stcp_socket.hpp>
#include <mail/message.hpp>
#include <fc/exception/exception.hpp>
#include <bts/bitchat/bitchat_private_message.hpp>
#include <bts/db/level_map.hpp>

namespace mail {
  
   namespace detail { class connection_impl; }

   class connection;
   struct message;
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
        
        void send( const message& m );
   
        void connect( const std::string& host_port );  
        void connect( const fc::ip::endpoint& ep );
        void close();

        fc::time_point get_last_sync_time()const;
        fc::time_point get_server_time()const;
        void           set_last_sync_time( const fc::time_point& );

        void exec_sync_loop();
        void set_database( bts::db::level_map<fc::time_point,bts::bitchat::encrypted_message>*  );

      private:
        std::unique_ptr<detail::connection_impl> my;
   };

    
} // mail
