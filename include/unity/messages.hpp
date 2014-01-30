#pragma once
#include <fc/reflect/reflect.hpp>
#include <fc/crypto/elliptic.hpp>
#include <set>

namespace unity 
{

   enum message_type
   {
       subscribe_msg = 1,
       blob_msg      = 2,
       proposal_msg  = 3
   };

   struct subscribe_message
   {
      static const message_type       type;
      uint16_t                        version;
      fc::time_point                  timestamp;
      fc::ecc::compact_signature      sig;

      fc::sha256                      digest()const;
      void                            sign( const fc::ecc::private_key& k );
      fc::ecc::public_key             signee()const;
   };

   struct blob_message
   {
      static const message_type type;
      std::vector<char>         blob;
   };

   struct proposal_message
   {
      static const message_type type;
      proposal_message(){}
      proposal_message( const unity::signed_proposal& t ):signed_prop(t){}
      signed_proposal    signed_prop;                 
   };


} // namespace unity

FC_REFLECT_ENUM( unity::message_type, (subscribe_msg)(blob_msg)(proposal_msg) )
FC_REFLECT( unity::subscribe_message, (version)(timestamp)(sig) )
FC_REFLECT( unity::blob_message, (blob) )
FC_REFLECT( unity::proposal_message, (signed_prop) )
