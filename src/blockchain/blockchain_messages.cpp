#include <bts/blockchain/blockchain_messages.hpp>

namespace bts { namespace blockchain {

const message_type trx_inv_message::type = trx_inv_msg;
const message_type block_inv_message::type = block_inv_msg;
const message_type get_trx_inv_message::type = get_trx_inv_msg;
const message_type get_block_inv_message::type = get_block_inv_msg;
const message_type get_trxs_message::type = get_trxs_msg;
const message_type get_full_block_message::type = get_full_block_msg;
const message_type get_trx_block_message::type = get_trx_block_msg;
const message_type trxs_message::type = trxs_msg;
const message_type full_block_message::type = full_block_msg;
const message_type trx_block_message::type = trx_block_msg;

} } // bts::bitchat
