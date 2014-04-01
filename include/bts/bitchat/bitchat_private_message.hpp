#pragma once
#include <bts/network/channel_id.hpp>
#include <bts/extended_address.hpp>
#include <fc/io/raw.hpp>
#include <fc/thread/future.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/ripemd160.hpp>
#include <fc/time.hpp>
#include <fc/optional.hpp>
#include <fc/io/enum_type.hpp>
#include <bts/db/upgrade_leveldb.hpp>

namespace bts { namespace bitchat {
    using network::channel_id;

    enum message_type
    {
       inv_msg             = 1, ///< publishes known active inventory
       cache_inv_msg       = 2, ///< publishes known historic inventory
       get_inv_msg         = 3, ///< requests active inventory
       get_cache_inv_msg   = 4, ///< requests historic inventory
       get_priv_msg        = 5, ///< sent to request an private message in the active inventory
       get_cache_priv_msg  = 6, ///< sent to request an private message in the historic inventory
       encrypted_msg       = 7, ///< a message encrypted to unknown receip (sent in reponse to get_priv_msg)
       server_info_msg     = 8, ///< a message that gives clients server stats
       client_info_msg     = 9  ///< a message that gives clients server stats
    };

    enum compression_type
    {
       no_compression   = 0,
       smaz_compression = 1,
       lzma_compression = 2
    };

    enum encryption_type
    {
       no_encryption       = 0,
       blowfish_encryption = 1,
       twofish_encryption  = 2,
       aes_encryption      = 3
    };

    struct decrypted_message;

    //legacy encrypted_message (had insufficient timestamp granularity)
    struct encrypted_message0 
    {
        static const message_type type;
        encrypted_message0();
        mutable uint32_t                              noncea; ///< collision a
        mutable uint32_t                              nonceb; ///< collision b

        uint16_t                                      nonce; ///< increment timestamp after 63K tests
        fc::time_point_sec                            timestamp;
        fc::ecc::public_key                           dh_key;
        fc::uint160_t                                 check;
        std::vector<char>                             data;

        fc::uint128        id()const;

        /**
         *  This method will increment the nonce or timestamp until difficulty(id()) > tar_per_kb*(1+data.size()/1024).
         *
         *  @return a future object that can be used to cancel the proof of work, result true if target found.
         */
        bool        do_proof_work( uint64_t tar_per_kb );
        bool        validate_proof()const; // checks to make sure the proof of work is valid
        uint64_t    difficulty()const;
        bool        decrypt( const fc::ecc::private_key& with, decrypted_message& m )const;
    };

    /**
     *  An encrypted message is encoded with a particular public key destination in
     *  mind.  Each message establishes a new ECDH key pair and one-time shared secret 
     *  to establish the blowfish decryption key.
     *
     *  TODO: add move semantics to encrypted_message
     */
    struct encrypted_message
    {
        static const message_type type;
        encrypted_message();
        encrypted_message(const encrypted_message0& msg) //upgrade from old encrypted_message format
          {
          noncea = msg.noncea;
          nonceb = msg.nonceb;
          nonce  = msg.nonce;
          timestamp = msg.timestamp; //switch from time_point_sec to high accuracy time_point
          dh_key = msg.dh_key;
          check = msg.check;
          data = msg.data;
          }

        mutable uint32_t                              noncea; ///< collision a
        mutable uint32_t                              nonceb; ///< collision b

        uint16_t                                      nonce; ///< increment timestamp after 63K tests
        fc::time_point                                timestamp;
        fc::ecc::public_key                           dh_key;
        fc::uint160_t                                 check;
        std::vector<char>                             data;

        fc::uint128        id()const;

        /**
         *  This method will increment the nonce or timestamp until difficulty(id()) > tar_per_kb*(1+data.size()/1024).
         *
         *  @return a future object that can be used to cancel the proof of work, result true if target found.
         */
        bool        do_proof_work( uint64_t tar_per_kb );
        bool        validate_proof()const; // checks to make sure the proof of work is valid
        uint64_t    difficulty()const;
        bool        decrypt( const fc::ecc::private_key& with, decrypted_message& m )const;
    };

    /** content of private_message data */
    enum private_message_type
    {
       unknown_msg          = 0,
       text_msg             = 1,
       email_msg            = 2,
       contact_request_msg  = 3,
       contact_auth_msg     = 4,
       status_msg           = 5,
       email_msg1           = 6 /// for private_email_message1
    };

    /**
     *  A decrypted message has a type, payload, timestamp and signature that allow us to
     *  derive the public key of the signer.  It is designed to be easily populated with
     *  many different types of messages that get serialized/deserialized into the data field.
     *
     *  TODO: add move semantics to decrypted_message
     */
    struct decrypted_message
    {
        template<typename T>
        decrypted_message( const T& msg )
        {
           msg_type = T::type;
           data = fc::raw::pack( msg );
        }

        template<typename T>
        T as()const
        {
           if( msg_type != T::type )
           {
              FC_THROW_EXCEPTION( bad_cast_exception, "Unable to cast ${msg_type} to ${type}",
                                                      ("msg_type",msg_type)("type",T::type) );
           }
           return fc::raw::unpack<T>( data );
        }

        decrypted_message();
        encrypted_message                    encrypt( const fc::ecc::public_key& to )const;
        decrypted_message&                   sign( const fc::ecc::private_key& from );
        fc::sha256                           digest()const;

        /** type of the decrypted, uncompressed message */
        fc::enum_type<fc::unsigned_int,private_message_type>  msg_type;
        std::vector<char>                                     data;

        fc::time_point                                        sig_time;
        fc::optional<fc::ecc::compact_signature>              from_sig;

        fc::optional<fc::ecc::public_key>                     from_key;
        fc::optional<fc::ecc::private_key>                    decrypt_key;
    };

    struct private_text_message 
    {
       static const private_message_type  type;

       private_text_message( std::string m = std::string())
       :msg( std::move(m) ){}
      
       std::string      msg;
    };

    enum authorization_status
    {
      request   = 0,
      accept    = 1,
      deny      = 2,
      block     = 3
    };

    struct private_contact_request_message 
    {
       static const private_message_type  type;

       std::string                                          from_first_name;
       std::string                                          from_last_name;
       std::string                                          from_keyhotee_id;
       uint16_t                                             request_param;
       std::string                                          greeting_message;///< message introducing name/key
       channel_id                                           from_channel;    ///< channel where from_name can be contacted
       bts::extended_public_key                             extended_pub_key;
       fc::enum_type<fc::unsigned_int,authorization_status> status;
       fc::ecc::public_key                                  recipient;
    };

    struct attachment
    {
      std::string       filename;
      std::vector<char> body;
    };

    struct private_email_message
    {
       static const private_message_type  type;
       std::string                        from_keyhotee_id;
       std::vector<fc::ecc::public_key>   to_list;
       std::vector<fc::ecc::public_key>   cc_list;
       std::string                        subject;
       std::string                        body;
       std::vector<attachment>            attachments;
       std::vector<fc::ecc::public_key>   bcc_list;
    };

    struct private_email_message1 : public private_email_message
    {
      private_email_message1(){}

      private_email_message1(const private_email_message& msg) //upgrade from old private_email_message format
      {
        from_keyhotee_id  = msg.from_keyhotee_id;
        to_list           = msg.to_list;
        cc_list           = msg.cc_list;
        subject           = msg.subject;
        body              = msg.body;
        attachments       = msg.attachments;
        bcc_list          = msg.bcc_list;
      }

      static const private_message_type  type;

      fc::optional<fc::uint256>          src_msg_id; /// id of the message to which replied or forwarded
    };

    struct private_contact_auth_message 
    {
       static const private_message_type  type;

       std::string                        auth_text;         ///< "sorry, ok, ..."
       fc::uint128                        min_work;          ///< how much work is required to contact this individual
       fc::time_point_sec                 expires;           ///< specifies when the channel list and broadcast key will expire.
       std::vector<network::channel_id>   listen_channels;   ///< channel where from_name can be contacted
       fc::optional<fc::ecc::private_key> broadcast_key;     ///< key used by this contact for broadcasting updates, updates
                                                             ///  are only valid if signed with the actual public key, anyone
                                                             ///  else 'publishing' with this broadcast key should be ignored.
    };


    enum account_status 
    {  
      unknown = 0, 
      active  = 1, 
      away    = 2,
      idle    = 3, 
      signoff = 4
    };

    /**
     *  Used to broadcast to those who you have shared your broadcast_key with that you
     *  are online, away, etc.
     */
    struct private_status_message 
    {
       static const private_message_type  type;

       private_status_message( account_status s = unknown, std::string m = std::string() )
       :status( s ), status_message( std::move(m) ){}
       fc::enum_type<fc::unsigned_int,account_status>  status;
       std::string     status_message;
    };

} }  // namespace bts::bitchat

#include <fc/reflect/reflect.hpp>
FC_REFLECT_ENUM( bts::bitchat::account_status, (unknown)(active)(away)(idle) )
FC_REFLECT_ENUM( bts::bitchat::message_type, 
       (inv_msg)
       (cache_inv_msg)
       (get_inv_msg)
       (get_cache_inv_msg)
       (get_priv_msg)
       (get_cache_priv_msg)
       (encrypted_msg) )

FC_REFLECT_ENUM( bts::bitchat::private_message_type, (unknown_msg)(text_msg)(email_msg)(contact_request_msg)(contact_auth_msg)(status_msg)(email_msg1) )
FC_REFLECT_ENUM( bts::bitchat::compression_type, (no_compression)(smaz_compression)(lzma_compression) )
FC_REFLECT_ENUM( bts::bitchat::encryption_type, (no_encryption)(blowfish_encryption)(twofish_encryption)(aes_encryption) )
FC_REFLECT_ENUM( bts::bitchat::authorization_status, (request)(accept)(deny)(block) )
FC_REFLECT( bts::bitchat::attachment, (filename)(body) )

FC_REFLECT( bts::bitchat::encrypted_message0, (noncea)(nonceb)(nonce)(timestamp)(dh_key)(check)(data) );
FC_REFLECT( bts::bitchat::encrypted_message, (noncea)(nonceb)(nonce)(timestamp)(dh_key)(check)(data) );

FC_REFLECT( bts::bitchat::decrypted_message, (msg_type)(data)(sig_time)(from_sig) )
FC_REFLECT( bts::bitchat::private_text_message, (msg) )

FC_REFLECT( bts::bitchat::private_email_message, (from_keyhotee_id)(to_list)(cc_list)(subject)(body)(attachments)(bcc_list) )
FC_REFLECT_DERIVED( bts::bitchat::private_email_message1, (bts::bitchat::private_email_message), (src_msg_id) )

FC_REFLECT( bts::bitchat::private_status_message, (status)(status_message) )
FC_REFLECT( bts::bitchat::private_contact_request_message, (from_first_name)(from_last_name)(from_keyhotee_id)(request_param)
                                                            (greeting_message)(from_channel)(extended_pub_key)(status)(recipient) )

