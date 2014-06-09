#pragma once
#include <leveldb/db.h>
#include <leveldb/comparator.h>
#include <fc/filesystem.hpp>
#include <fc/reflect/reflect.hpp>
#include <fc/io/raw.hpp>
#include <fc/exception/exception.hpp>
#include <fc/crypto/aes.hpp>

#include "upgrade_leveldb.hpp"

namespace bts { namespace db {

  namespace ldb = leveldb;

  /**
   *  @brief implements a high-level API on top of Level DB that stores items using fc::raw / reflection
   *
   *
   *  @note Key must be a POD type
   */
  template<typename Key, typename Value>
  class level_pod_map
  {
     public:
        void open( const fc::path& dir, bool create = true )
        {
          open_encrypted(dir,create);
        }
        void open_encrypted( const fc::path& dir,  bool create = true, fc::optional<fc::uint512> encrypt_key = fc::optional<fc::uint512>() )
        {
          _encrypt_key = encrypt_key;
           ldb::Options opts;
           opts.create_if_missing = create;
           opts.comparator = & _comparer;
           

           /// \waring Given path must exist to succeed toNativeAnsiPath
           fc::create_directories(dir);

           std::string ldb_path = dir.to_native_ansi_path();

           ldb::DB* ndb = nullptr;
           auto ntrxstat = ldb::DB::Open( opts, ldb_path.c_str(), &ndb );
           if( !ntrxstat.ok() )
           {
               FC_THROW_EXCEPTION( db_in_use_exception, "Unable to open database ${db}\n\t${msg}", 
                    ("db",dir)
                    ("msg",ntrxstat.ToString()) 
                    );
           }
           _db.reset(ndb);
           UpgradeDbIfNecessary(dir,ndb, fc::get_typename<Value>::name(),sizeof(Value),_encrypt_key);
        }

        void close()
        {
          _db.reset();
        }

        Value fetch( const Key& key )
        {
          try {
             ldb::Slice key_slice( (char*)&key, sizeof(key) );
             std::string value_string;
             auto status = _db->Get( ldb::ReadOptions(), key_slice, &value_string );
             if( status.IsNotFound() )
             {
               FC_THROW_EXCEPTION( fc::key_not_found_exception, "unable to find key ${key}", ("key",key) );
             }
             if( !status.ok() )
             {
                 FC_THROW_EXCEPTION( fc::exception, "database error: ${msg}", ("msg", status.ToString() ) );
             }
             std::vector<char> value(value_string.begin(),value_string.end());
             if (_encrypt_key)
               value = fc::aes_decrypt( *_encrypt_key, value );

             fc::datastream<const char*> datastream(value.data(), value.size());
             Value tmp;
             fc::raw::unpack(datastream, tmp);
             return tmp;
          } FC_RETHROW_EXCEPTIONS( warn, "error fetching key ${key}", ("key",key) );
        }
        
        class iterator
        {
           public:
             iterator(){} //used to construct an invalid iterator to check against
             bool valid()const 
             {
                return _it && _it->Valid(); 
             }

             Key key()const
             {
                 FC_ASSERT( sizeof(Key) == _it->key().size() );
                 return *((Key*)_it->key().data());
             }

             Value value()const
             {
               Value tmp_val;
               leveldb::Slice slice(_it->value());
               std::vector<char> packed_value(slice.data(), slice.data()+slice.size());
               if (_level_pod_map->_encrypt_key)
                 packed_value = fc::aes_decrypt( *_level_pod_map->_encrypt_key, packed_value );
               fc::datastream<const char*> ds(packed_value.data(), packed_value.size()  );
               fc::raw::unpack( ds, tmp_val );
               return tmp_val;
             }

             iterator& operator++() { _it->Next(); return *this; }
             iterator& operator--() { _it->Prev(); return *this; }
           
           protected:
             friend class level_pod_map;
             iterator( ldb::Iterator* it, level_pod_map<Key,Value>* level_pod_map )
             :_it(it), _level_pod_map(level_pod_map){}

             std::shared_ptr<ldb::Iterator> _it;
             level_pod_map<Key,Value>*      _level_pod_map;
        };
        iterator begin() 
        { try {
           iterator itr( _db->NewIterator( ldb::ReadOptions() ), this );
           itr._it->SeekToFirst();

           if( itr._it->status().IsNotFound() )
           {
             FC_THROW_EXCEPTION( fc::key_not_found_exception, "" );
           }
           if( !itr._it->status().ok() )
           {
               FC_THROW_EXCEPTION( fc::exception, "database error: ${msg}", ("msg", itr._it->status().ToString() ) );
           }

           if( itr.valid() )
           {
              return itr;
           }
           return iterator();
        } FC_RETHROW_EXCEPTIONS( warn, "error seeking to first" ) }

        iterator find( const Key& key )
        { try {
           ldb::Slice key_slice( (char*)&key, sizeof(key) );
           iterator itr( _db->NewIterator( ldb::ReadOptions() ), this );
           itr._it->Seek( key_slice );
           if( itr.valid() && itr.key() == key ) 
           {
              return itr;
           }
           return iterator();
        } FC_RETHROW_EXCEPTIONS( warn, "error finding ${key}", ("key",key) ) }

        iterator lower_bound( const Key& key )
        { try {
           ldb::Slice key_slice( (char*)&key, sizeof(key) );
           iterator itr( _db->NewIterator( ldb::ReadOptions() ), this );
           itr._it->Seek( key_slice );
           if( itr.valid()  ) 
           {
              return itr;
           }
           return iterator();
        } FC_RETHROW_EXCEPTIONS( warn, "error finding ${key}", ("key",key) ) }


        bool last( Key& k )
        {
          try {
             std::unique_ptr<ldb::Iterator> it( _db->NewIterator( ldb::ReadOptions() ) );
             FC_ASSERT( it != nullptr );
             it->SeekToLast();
             if( !it->Valid() )
             {
               return false;
             }
             FC_ASSERT( sizeof( Key) == it->key().size() );
             k = *((Key*)it->key().data());
             return true;
          } FC_RETHROW_EXCEPTIONS( warn, "error reading last item from database" );
        }

        bool last( Key& k, Value& v )
        {
          try {
           std::unique_ptr<ldb::Iterator> it( _db->NewIterator( ldb::ReadOptions() ) );
           FC_ASSERT( it != nullptr );
           it->SeekToLast();
           if( !it->Valid() )
           {
             return false;
           }
           leveldb::Slice slice(it->value());
           std::vector<char> packed_value(slice.data(), slice.data()+slice.size());
           if (_encrypt_key)
             packed_value = fc::aes_decrypt( *_encrypt_key, packed_value );
           fc::datastream<const char*> ds( packed_value.data(), packed_value.size() );
           fc::raw::unpack( ds, v );

           FC_ASSERT( sizeof( Key) == it->key().size() );
           k = *((Key*)it->key().data());
           return true;
          } FC_RETHROW_EXCEPTIONS( warn, "error reading last item from database" );
        }

        void store( const Key& k, const Value& v )
        {
          try
          {
             ldb::Slice ks( (char*)&k, sizeof(k) );
             auto vec = fc::raw::pack(v);
             if (_encrypt_key)
              vec = fc::aes_encrypt( *_encrypt_key, vec );
             ldb::Slice vs( vec.data(), vec.size() );             
             auto status = _db->Put( ldb::WriteOptions(), ks, vs );
             if( !status.ok() )
             {
                 FC_THROW_EXCEPTION( fc::exception, "database error: ${msg}", ("msg", status.ToString() ) );
             }
          } FC_RETHROW_EXCEPTIONS( warn, "error storing ${key} = ${value}", ("key",k)("value",v) );
        }

        void remove( const Key& k )
        {
          try
          {
            ldb::Slice ks( (char*)&k, sizeof(k) );
            auto status = _db->Delete( ldb::WriteOptions(), ks );

            if( status.IsNotFound() )
            {
              FC_THROW_EXCEPTION( fc::key_not_found_exception, "unable to find key ${key}", ("key",k) );
            }
            if( !status.ok() )
            {
                FC_THROW_EXCEPTION( fc::exception, "database error: ${msg}", ("msg", status.ToString() ) );
            }
          } FC_RETHROW_EXCEPTIONS( warn, "error removing ${key}", ("key",k) );
        }
        

     private:
        class key_compare : public leveldb::Comparator
        {
          public:
            int Compare( const leveldb::Slice& a, const leveldb::Slice& b )const
            {
               FC_ASSERT( (a.size() == sizeof(Key)) && (b.size() == sizeof( Key )) );
               Key* ak = (Key*)a.data();        
               Key* bk = (Key*)b.data();        
               if( *ak  < *bk ) return -1;
               if( *ak == *bk ) return 0;
               return 1;
            }

            const char* Name()const { return "key_compare"; }
            void FindShortestSeparator( std::string*, const leveldb::Slice& )const{}
            void FindShortSuccessor( std::string* )const{};
        };

        key_compare                  _comparer;
        std::unique_ptr<leveldb::DB> _db;
        fc::optional<fc::uint512>    _encrypt_key;
        
  };


} } // bts::db
