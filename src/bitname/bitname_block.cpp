#include <bts/bitname/bitname_block.hpp>
#include <bts/difficulty.hpp>
#include <fc/crypto/bigint.hpp>
#include <fc/io/raw.hpp>
#include <fc/crypto/city.hpp>
#include <algorithm>

#include <fc/log/logger.hpp>

namespace bts { namespace bitname {

  name_id_type  name_header::id()const
  {
    name_id_type::encoder enc;
    fc::raw::pack(enc,*this);
    return enc.result();
  }

  short_name_id_type name_header::short_id()const
  {
     auto long_id = id();
     return (short_name_id_type)long_id._hash[1] << 32 | long_id._hash[0];
  }


  uint64_t name_header::difficulty()const
  {
      return bts::difficulty(id());
  }

  uint64_t name_block::block_difficulty()const
  {
     uint64_t sum = 0;
     for( auto itr = name_trxs.begin(); itr != name_trxs.end(); ++itr )
     {
       sum += itr->difficulty( prev ); 
     }
     if( sum > 0 )
     {
         return difficulty() + sum;
     }
     /**
      *   The difficulty of the block header must be more than the sum of the difficulties of
      *   the contained transactions.
      */
     return difficulty()/2;
  }

  name_trxs_hash_type name_block::calc_trxs_hash()const
  {
     fc::sha512::encoder enc;
     fc::raw::pack( enc, prev );
     fc::raw::pack( enc, name_trxs );
     auto result = enc.result();
     // city hash isn't crypto secure, but its input is sha512 which is.
     // we use city to compress the hash for bandwidth purposes
     return fc::city_hash128( (char*)&result, sizeof(result) );
  }

  /** helper method */
  name_id_type name_trx::id( const name_id_type& prev )const
  {
    return name_header( *this, prev ).id();
  }
  /** helper method */
  short_name_id_type name_trx::short_id( const name_id_type& prev )const
  {
    return name_header( *this, prev ).short_id();
  }

  uint64_t name_trx::difficulty( const name_id_type& prev )const
  {
    return name_header( *this, prev ).difficulty();
  }

  #define HARD_MINING
  const name_id_type& max_name_hash()
  {
     static name_id_type max_hash = []() -> name_id_type {
         name_id_type tmp;
         //set initial difficulty
         char* tmpPtr = (char*)&tmp;
         memset( tmpPtr, 0xff, sizeof(tmp) );
         //set initial difficulty low for debugging and testing
         #ifdef EASY_MINING
         //initialize to 0x00ff...ff
         tmpPtr[0] = 0;
         #else  //set higher initial difficulty for release version of mining (//initialize to 0x00000f...ff)         
           #ifdef HARD_MINING
           tmpPtr[0] = 0;
           tmpPtr[1] = 0;
           tmpPtr[2] = 0;
           tmpPtr[3] = 0x0f;
           #else
           tmpPtr[0] = 0;
           tmpPtr[1] = 0;
           tmpPtr[2] = 0x0f;
           #endif
         #endif
         return tmp;
     }();
     return max_hash;
  }

  uint64_t min_name_difficulty() 
  {
      return difficulty(max_name_hash()); 
  }

  name_block create_genesis_block()
  {
     name_block genesis;
     genesis.utc_sec = fc::time_point_sec(fc::time_point::from_iso_string( "20130822T183833" ));
     genesis.name_hash = 0;
     genesis.master_key = fc::ecc::private_key::regenerate(fc::sha256::hash( "genesis", 7)).get_public_key();
     genesis.active_key = genesis.master_key; //fc::ecc::private_key::regenerate(fc::sha256::hash( "genesis", 7)).get_public_key();
     return genesis;
  }

} }
