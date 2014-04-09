#pragma once
#include <leveldb/db.h>
#include <leveldb/comparator.h>
#include <fc/filesystem.hpp>
#include <fc/reflect/reflect.hpp>
#include <fc/io/raw.hpp>
#include <fc/exception/exception.hpp>
#include <fc/crypto/sha512.hpp>
#include <functional>
#include <map>
#include <boost/regex.hpp>
// this code has no bitshares dependencies, and it
// could be moved to fc, if fc ever adds a leveldb dependency

// This code enables legacy databases files created by older programs to
// be upgraded to the current database formats. Whenever a database is first opened,
// this code check if the database is stored in an old format and looks for an
// upgrade function to upgrade it to the current format. If found, the objects
// in the database will be immediately upgraded to the current format.

// Upgrades are performed  by executing a series of chained copy constructors
// from the legacy object format to the current object format. This means
// that only one new copy constructor typically needs to be written to support
// upgrading any previous version of the object when an object type is modified.

//*Database versioning is only supported for changes to database value types
// (databases with modified key types cannot currently be upgraded).
//*The database versioning code requires that fc::get_typename is defined for
// all value types which are to be versioned.

/*
Below is a simple example of how client code needs to be written to support
database versioning. Originally, a database stored values of record0, and
record was typedef'd to be record0. A new type record1 was created to add
"new_field" to record type, and record was typedef'd to record1. The typedef
is used to minimize required changes to the client code that references
record objects.

struct record0
{
    record0() : points(0) {}
    double    points;
};
FC_REFLECT( record0, (points) )
REGISTER_DB_OBJECT(record,0) //This creates an upgrade function for record0 databases

struct record1
{
    record1() : points(0), new_field("EMPTY") {}
    
    record1(const record0& r0) //convert from record0 to record1 for legacy files
      {
      key = r0.key;
      new_field = "EMPTY";
      }
    std::string new_field; 
    double    points;
};
FC_REFLECT( record1, (points)(new_field) )

typedef record1 record; //current databases store record1 objects
*/

typedef std::function<void(leveldb::DB*,fc::optional<fc::uint512>)> TUpgradeDbFunction; 
class TUpgradeDbMapper
{
  static TUpgradeDbMapper* _updateDbMapper;
public:
  static TUpgradeDbMapper* Instance()
       {
       if (!_updateDbMapper)
         _updateDbMapper = new TUpgradeDbMapper();
       return _updateDbMapper;
       }
  std::map<std::string,TUpgradeDbFunction> UpgradeDbFunctionRegistry;
  int Add(std::string typeName, TUpgradeDbFunction function) 
       { 
       UpgradeDbFunctionRegistry.insert( std::map<std::string,TUpgradeDbFunction>::value_type(typeName,function) );
       return 0;
       }
};

#define REGISTER_DB_OBJECT(TYPE,VERSIONNUM) \
void UpgradeDb ## TYPE ## VERSIONNUM(leveldb::DB* dbase, fc::optional<fc::uint512> encrypt_key) \
  { \
  std::unique_ptr<leveldb::Iterator> dbaseI( dbase->NewIterator(leveldb::ReadOptions()) ); \
  dbaseI->SeekToFirst(); \
  if (dbaseI->status().IsNotFound()) /*if empty database, do nothing*/ \
    return; \
  if (!dbaseI->status().ok()) \
    FC_THROW_EXCEPTION( exception, "database error: ${msg}", ("msg", dbaseI->status().ToString() ) ); \
  while (dbaseI->Valid()) /* convert dbase objects from legacy TypeVersionNum to current Type */ \
    { \
    TYPE ## VERSIONNUM old_value; /*load old record type*/ \
    leveldb::Slice slice(dbaseI->value()); \
    std::vector<char> packed_value(slice.data(), slice.data()+slice.size()); \
    if (encrypt_key) \
      packed_value = fc::aes_decrypt( *encrypt_key, packed_value ); \
    fc::datastream<const char*> dstream(packed_value.data(), packed_value.size()  ); \
    fc::raw::unpack( dstream, old_value ); \
    TYPE new_value(old_value);       /*convert to new record type*/ \
    leveldb::Slice key_slice = dbaseI->key(); \
    packed_value = fc::raw::pack(new_value); \
    if (encrypt_key) \
      packed_value = fc::aes_encrypt( *encrypt_key, packed_value ); \
    leveldb::Slice value_slice( packed_value.data(), packed_value.size() ); \
    auto status = dbase->Put( leveldb::WriteOptions(), key_slice, value_slice ); \
    if( !status.ok() ) \
      { \
      FC_THROW_EXCEPTION( exception, "database error: ${msg}", ("msg", status.ToString() ) ); \
      } \
    dbaseI->Next(); \
    } /*while*/ \
  } \
static int dummyResult ## TYPE ## VERSIONNUM  = \
  TUpgradeDbMapper::Instance()->Add(fc::get_typename<TYPE ## VERSIONNUM>::name(), UpgradeDb ## TYPE ## VERSIONNUM);

void UpgradeDbIfNecessary(fc::path dir, leveldb::DB* dbase, const char* record_type, size_t record_type_size, fc::optional<fc::uint512> encrypt_key);