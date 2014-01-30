#pragma once
#include <unity/node.hpp>
#include <fc/reflect/reflect.hpp>

namespace unity 
{
   namespace detail { class server_impl; }

   /**
    *  Provides network communication layer to synchronize unity::node's.
    *
    */
   class server
   {
      public:
         server();
         ~server();

         struct config
         {
             uint16_t                   unity_port;
             std::vector<std::string>   hosts;
             unity::config              node_config;
         };

         void configure( const server::config& cfg );
      
      private:
         std::unique_ptr<detail::server_impl> my;
   };
} // namespace unity

FC_REFLECT( unity::server::config, (unity_port)(hosts)(node_config) )
