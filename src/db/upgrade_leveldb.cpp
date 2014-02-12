#include <bts/db/upgrade_leveldb.hpp>

TUpgradeDbMapper gUpgradeDbMapper;
// this code has no bitshares dependencies, and it
// could be moved to fc, if fc ever adds a leveldb dependency
void UpgradeDbIfNecessary(leveldb::DB* dbase, const char* current_record_name )
  {
  std::unique_ptr<leveldb::Iterator> dbaseI( dbase->NewIterator( leveldb::ReadOptions() ) );
  leveldb::Slice key_slice( "RECORD_TYPE" );
  dbaseI->Seek( key_slice );
  std::string recordType;
  if( dbaseI->Valid() && key_slice == dbaseI->key() ) 
    {
    recordType = dbaseI->value().ToString();
    }
  else //no RECORD_TYPE, must be original type for the database
    { //strip record version from current_record_name and append 0
    recordType = current_record_name;
    int lastChar = recordType.length() - 1;
    assert(isdigit(recordType[lastChar])); //record types should always end with version number
    while (isdigit(recordType[lastChar]))
      {
      --lastChar;
      }
    ++lastChar;
    recordType[lastChar] = '0';
    recordType.resize(lastChar+1);
    }
  //check if upgrade function in registry
  auto upgrade_functionI = gUpgradeDbMapper.UpgradeDbFunctionRegistry.find( recordType );
  if (upgrade_functionI != gUpgradeDbMapper.UpgradeDbFunctionRegistry.end())
    {
    //update database's RECORD_TYPE to new record type name
    leveldb::Slice value_slice( current_record_name );
    dbase->Put( leveldb::WriteOptions(), key_slice, value_slice );
    //upgrade the database using upgrade function
    upgrade_functionI->second(dbase);
    }
  }