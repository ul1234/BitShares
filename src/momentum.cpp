#include <bts/momentum.hpp>
#include <fc/thread/thread.hpp>
#include <fc/crypto/ripemd160.hpp>
#include <fc/crypto/sha1.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/crypto/sha512.hpp>
#include <fc/crypto/aes.hpp>

#include <unordered_map>
#include <fc/reflect/variant.hpp>
#include <fc/time.hpp>
#include <algorithm>
#include <array>

#include <fc/log/logger.hpp>


namespace bts 
{
   #define MAX_MOMENTUM_NONCE  (1<<26)
   #define SEARCH_SPACE_BITS 50
   #define BIRTHDAYS_PER_HASH 8

  //Reduced hash table size to accomodate machines with less ram
  //and to avoid problems on WIN32 with allocating large contiguous blocks
  //of memory.
  const int TABLE_SIZE =  (1<<25);

  class hashtable
  {
     public:
        hashtable() :
            itable(new std::array< std::pair<uint64_t,uint32_t>,TABLE_SIZE >),
            table(*itable)
        {
            reset();
        }
        ~hashtable()
        {
            delete itable;
        }
        void reset()
        {
            memset( (char*)table.data(), 0, table.size()*sizeof(std::pair<uint64_t,uint32_t>) );
        }

        uint32_t store( uint64_t key, uint32_t val )
        {
           uint64_t next_key = key;
           auto index = next_key % table.size() ;

           //if matching collision in table, return it
           if( table[index].first == key  )
           {
               return table[index].second;
           }

           //no collision, add to table
           table[index].first   = key;
           table[index].second  = val;
           return -1;
        }


     private:
        std::array< std::pair<uint64_t,uint32_t>,TABLE_SIZE >*  itable;
        std::array< std::pair<uint64_t,uint32_t>,TABLE_SIZE >&  table;
  };


    
   std::vector< std::pair<uint32_t,uint32_t> > momentum_search( pow_seed_type head )
   {
      hashtable found;
      std::vector< std::pair<uint32_t,uint32_t> > results;

      for( uint32_t i = 0; i < MAX_MOMENTUM_NONCE;  )
      {
          fc::sha512::encoder enc;
          enc.write( (char*)&i, sizeof(i) );
          enc.write( (char*)&head, sizeof(head) );

          auto result = enc.result();
        
          for( uint32_t x = 0; x < 8; ++x )
          {
              uint64_t birthday = result._hash[x] >> 14;
              uint32_t nonce = i+x;
              uint32_t cur = found.store( birthday, nonce );
              if( cur != uint32_t(-1) )
              {
                  results.push_back( std::make_pair( cur, nonce ) );
                  results.push_back( std::make_pair( nonce, cur ) );
              }
          }
          i += 8;
      }
      return results;
   }


   bool momentum_verify( pow_seed_type head, uint32_t a, uint32_t b )
   {
       if( a == b ) return false;
       if( a > MAX_MOMENTUM_NONCE ) return false;
       if( b > MAX_MOMENTUM_NONCE ) return false;

       uint32_t ia = (a / 8) * 8; 
       fc::sha512::encoder enca;
       enca.write( (char*)&ia, sizeof(ia) );
       enca.write( (char*)&head, sizeof(head) );
       auto ar = enca.result();

       uint32_t ib = (b / 8) * 8; 
       fc::sha512::encoder encb;
       encb.write( (char*)&ib, sizeof(ib) );
       encb.write( (char*)&head, sizeof(head) );
       auto br = encb.result();

       return (ar._hash[a%8]>>14) == (br._hash[b%8]>>14);
   }

}
