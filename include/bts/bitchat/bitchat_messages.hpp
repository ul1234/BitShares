#pragma once
#include <bts/bitchat/bitchat_private_message.hpp>
#include <fc/network/ip.hpp>

namespace bts { namespace bitchat {

  // other protocol messages... not encapsulated by data_message
  struct inv_message 
  {
      static const message_type type;
      std::vector<fc::uint128>  items;
  };

  // other protocol messages... not encapsulated by data_message
  struct cache_inv_message 
  {
      static const message_type type;
      std::vector<fc::uint128>  items;
  };

  struct get_priv_message
  {
      static const message_type type;
      get_priv_message(){}
      get_priv_message( const fc::uint128& p )
      {
        items.push_back(p);
      }
      std::vector<fc::uint128>  items;
  };
  struct get_cache_priv_message
  {
      static const message_type type;
      get_cache_priv_message(){}
      get_cache_priv_message( const fc::uint128& p )
      {
        items.push_back(p);
      }
      get_cache_priv_message( const std::vector<fc::uint128>& i )
      :items(i)
      {}

      std::vector<fc::uint128>  items;
  };

  /**
   *  Used to request all inventory after the given time.
   */
  struct get_inv_message
  {
      static const message_type type;
      fc::time_point_sec after;
  };

  /**
   *  
   */
  struct get_cache_inv_message
  {
      static const message_type type;
      get_cache_inv_message( const fc::time_point& s, const fc::time_point e )
      :start_time(s),end_time(e){}
      get_cache_inv_message(){}
      fc::time_point_sec start_time;
      fc::time_point_sec end_time;
  };

  struct server_info_message
  {
      static const message_type type;
      server_info_message()
      :version(0){}

      uint16_t                        version;
      fc::time_point                  server_time;
      std::vector<fc::ip::endpoint>   mirrors;
      uint64_t                        current_difficulty;
  };

  struct client_info_message
  {
      static const message_type type;
      client_info_message()
      :version(0){}

      uint16_t                        version;
      fc::time_point                  sync_time;
  };

} } // bts::bitchat

FC_REFLECT( bts::bitchat::inv_message,      (items) )
FC_REFLECT( bts::bitchat::get_priv_message, (items) )
FC_REFLECT( bts::bitchat::get_inv_message,  (after) )

FC_REFLECT( bts::bitchat::cache_inv_message,      (items) )
FC_REFLECT( bts::bitchat::get_cache_priv_message, (items) )
FC_REFLECT( bts::bitchat::get_cache_inv_message,  (start_time)(end_time) )
FC_REFLECT( bts::bitchat::server_info_message,  (version)(server_time)(mirrors)(current_difficulty) )
FC_REFLECT( bts::bitchat::client_info_message, (version)(sync_time) )
