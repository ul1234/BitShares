#pragma once
#include <fc/reflect/reflect.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/array.hpp>
#include <string>

namespace bts
{
   /**
    *  Implements address stringification and validation from PTS
    */
   struct pts_address
   {
       pts_address(); ///< constructs empty / null address
       pts_address( const std::string& base58str );   ///< converts to binary, validates checksum
       pts_address( const fc::ecc::public_key& pub, bool compressed = false ); ///< converts to binary

       bool is_valid()const;

       operator std::string()const; ///< converts to base58 + checksum

       fc::array<char,25> addr; ///< binary representation of address
   };

   inline bool operator == ( const pts_address& a, const pts_address& b ) { return a.addr == b.addr; }
   inline bool operator != ( const pts_address& a, const pts_address& b ) { return a.addr != b.addr; }
   inline bool operator <  ( const pts_address& a, const pts_address& b ) { return a.addr <  b.addr; }

} // namespace bts

FC_REFLECT( bts::pts_address, (addr) )

namespace fc 
{ 
   void to_variant( const bts::pts_address& var,  fc::variant& vo );
   void from_variant( const fc::variant& var,  bts::pts_address& vo );
}

namespace std
{
   template<>
   struct hash<bts::pts_address> 
   {
       public:
         size_t operator()(const bts::pts_address &a) const 
         {
            size_t s;
            memcpy( (char*)&s, &a.addr.data[sizeof(a)-sizeof(s)], sizeof(s) );
            return s;
         }
   };
}
