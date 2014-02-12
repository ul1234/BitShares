#pragma once
#include <leveldb/db.h>
#include <leveldb/comparator.h>
#include <fc/filesystem.hpp>
#include <fc/reflect/reflect.hpp>
#include <fc/io/raw.hpp>
#include <fc/exception/exception.hpp>
#include <functional>
#include <map>
#include <boost/regex.hpp>
// this code has no bitshares dependencies, and it
// could be moved to fc, if fc ever adds a leveldb dependency

typedef std::function<void(leveldb::DB*)> TUpgradeDbFunction; 
class TUpgradeDbMapper
{
public:
  std::map<std::string,TUpgradeDbFunction> UpgradeDbFunctionRegistry;
  int Add(std::string typeName, TUpgradeDbFunction function) 
       { 
       UpgradeDbFunctionRegistry.insert( std::map<std::string,TUpgradeDbFunction>::value_type(typeName,function) );
       return 0;
       }
};

extern TUpgradeDbMapper gUpgradeDbMapper;
#define REGISTER_DB_OBJECT(TYPE,VERSIONNUM) \
void UpgradeDb ## TYPE ## VERSIONNUM(leveldb::DB* dbase) \
  { \
  std::unique_ptr<leveldb::Iterator> dbaseI = dbase->NewIterator( leveldb::ReadOptions() ); \
  dbaseI->SeekToFirst(); \
  if (dbaseI->status().IsNotFound()) /*if empty database, do nothing*/ \
    return; \
  if (!dbaseI->status().ok()) \
    FC_THROW_EXCEPTION( exception, "database error: ${msg}", ("msg", dbaseI->status().ToString() ) ); \
  while (dbaseI->Valid()) /* convert dbase objects from legacy TypeVersionNum to current Type */ \
    { \
    TYPE ## VERSIONNUM old_value; /*load old record type*/ \
    fc::datastream<const char*> dstream( dbaseI->value().data(), dbaseI->value().size() ); \
    fc::raw::unpack( dstream, old_value ); \
    TYPE new_value(old_value);       /*convert to new record type*/ \
    leveldb::Slice key_slice = dbaseI->key(); \
    auto vec = fc::raw::pack(new_value); \
    leveldb::Slice value_slice( vec.data(), vec.size() ); \
    auto status = dbase->Put( leveldb::WriteOptions(), key_slice, value_slice ); \
    if( !status.ok() ) \
      { \
      FC_THROW_EXCEPTION( exception, "database error: ${msg}", ("msg", status.ToString() ) ); \
      } \
    dbaseI->Next(); \
    } /*while*/ \
  } \
static int dummyResult ## TYPE ## VERSIONNUM  = \
  gUpgradeDbMapper.Add(fc::get_typename<TYPE ## VERSIONNUM>::name(), UpgradeDb ## TYPE ## VERSIONNUM);

void UpgradeDbIfNecessary(leveldb::DB* dbase, const char* current_record_name );