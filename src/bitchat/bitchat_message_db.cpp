#include <bts/bitchat/bitchat_message_db.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/exception/exception.hpp>
#include <bts/db/level_pod_map.hpp>






namespace bts { namespace bitchat {
  
  bool operator < ( const message_header& a, const message_header& b )
  {
     if( a.type.value < b.type.value ) return true;
     if( a.type.value > b.type.value ) return false;
     if( a.received_time < b.received_time ) return true;
     if( a.received_time > b.received_time ) return false;
     if( a.to_key < b.to_key ) return true;
     if( a.to_key > b.to_key ) return false;
     if( a.from_key < b.from_key ) return true;
     return false;
  }

  bool operator == ( const message_header& a, const message_header& b )
  {
     return a.type == b.type &&
            a.received_time == b.received_time &&
            a.to_key == b.to_key &&
            a.from_key == b.from_key &&
            a.digest == b.digest;
            // TODO: compare the rest of it...
  }
  namespace detail 
  {
     class message_db_impl
     {
       public:
          db::level_pod_map<message_header,uint32_t>    _index;
          db::level_pod_map<fc::uint256,std::vector<char> > _digest_to_data;
          db::level_pod_map<fc::uint256, message_header>    _digest_to_header;
     };

  } // namespace detail

  message_db::message_db()
  :my( new detail::message_db_impl() )
  {
  }

  message_db::~message_db(){}

  void message_db::open( const fc::path& dbdir, const fc::uint512& key, bool create )
  { try {
        fc::create_directories(dbdir);
        my->_index.open(dbdir/"index");
        my->_digest_to_data.open(dbdir/"digest_to_data");
        my->_digest_to_header.open(dbdir/"digest_to_header");
  } FC_RETHROW_EXCEPTIONS( warn, "", ("dir", dbdir)("key",key)("create",create)) }

  message_header message_db::store_message(const decrypted_message& msg,
                                           const message_header* previous_msg_header )
  { try {
      if (previous_msg_header)
        my->_index.remove(*previous_msg_header);
  
      FC_ASSERT( msg.from_sig    );
      FC_ASSERT( msg.from_key    );
      FC_ASSERT( msg.decrypt_key );

      message_header header;
      header.type             = msg.msg_type;
      header.received_time    = fc::time_point::now();
      header.to_key           = msg.decrypt_key->get_public_key();
      header.from_key         = *msg.from_key;
      header.digest           = msg.digest();
      header.from_sig_time    = msg.sig_time;
      header.from_sig         = *msg.from_sig;
      my->_index.store(header,0);

      // TODO: consider using city128 rather than 256 to reduce index size
      my->_digest_to_data.store( header.digest, msg.data );
      my->_digest_to_header.store( header.digest, header );
      return header;
  } FC_RETHROW_EXCEPTIONS( warn, "", ("msg",msg) ) }
 
  //remove entire message (msg_header and message contents)
  void message_db::remove_message(const message_header& msg_header)
  {
      my->_index.remove(msg_header);    
      my->_digest_to_data.remove(msg_header.digest);
      my->_digest_to_header.remove(msg_header.digest);
  }

  //update field in header only. If you modify a field in the msg_header that's
  //used for equivalence, you need to first remove the unmodified form of the msg_header.
  void message_db::store_message_header(const message_header& msg_header)
  {
      my->_index.store(msg_header,0);
      my->_digest_to_header.store(msg_header.digest, msg_header);
  } 

  void message_db::remove_message_header(const message_header& msg_header)
  {
      my->_index.remove(msg_header);
      my->_digest_to_header.remove(msg_header.digest);
  } 

  std::vector<message_header>  message_db::fetch_headers( private_message_type t, 
                                              fc::time_point_sec from_time, 
                                              fc::time_point_sec to_time,
                                              fc::optional<fc::ecc::public_key_data> to_key,
                                              fc::optional<fc::ecc::public_key_data> from_key )
  { try {
     std::vector<message_header> headers;
     message_header start;
     start.type = t;
     start.received_time = from_time;
     if( to_key ) start.to_key = *to_key;
     auto itr = my->_index.lower_bound(start);

     while( itr.valid() )
     {
        auto cur_val = itr.key();
        if (cur_val.received_time >= static_cast<const fc::time_point&>(from_time))
        {
          if (cur_val.received_time <= static_cast<const fc::time_point&>(to_time))
            {
               if( to_key && *to_key != cur_val.to_key )
               {
                   ++itr;
                   continue;
               }
               headers.push_back(cur_val);
            }
            else
            {
               return headers;
            }
        }
        else
        {
           return headers;
        }
        ++itr;
     }

     return headers;
  } FC_RETHROW_EXCEPTIONS( warn, "", ("type",t)("from_time",from_time)("to_time",to_time)("to_key",to_key)("from_key",from_key) ) }
  
  std::vector<char> message_db::fetch_data(  const fc::uint256& digest )
  { try {
     return my->_digest_to_data.fetch(digest);
  } FC_RETHROW_EXCEPTIONS( warn, "", ("digest",digest ) ) }

  message_header message_db::fetch_header(const fc::uint256& digest)
  {
    try
    {
      return my->_digest_to_header.fetch(digest);
    } FC_RETHROW_EXCEPTIONS( warn, "", ("digest",digest))
  }

} } // bts::bitchat
