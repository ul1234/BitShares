#include <bts/bitchat/bitchat_messages.hpp>

namespace bts { namespace bitchat {

const message_type inv_message::type = message_type::inv_msg;
const message_type get_priv_message::type = message_type::get_priv_msg;
const message_type get_inv_message::type = message_type::get_inv_msg;
const message_type cache_inv_message::type = message_type::cache_inv_msg;
const message_type get_cache_priv_message::type = message_type::get_cache_priv_msg;
const message_type get_cache_inv_message::type = message_type::get_cache_inv_msg;
const message_type encrypted_message::type = message_type::encrypted_msg;
const message_type server_info_message::type = message_type::server_info_msg;
const message_type client_info_message::type = message_type::client_info_msg;

} } // bts::bitchat

