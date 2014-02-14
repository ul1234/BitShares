#include <bts/db/upgrade_leveldb.hpp>
#include <boost/filesystem.hpp>
#include <fc/log/logger.hpp>

#include <bts/addressbook/contact.hpp>
namespace bts { namespace addressbook {
REGISTER_DB_OBJECT(wallet_identity,0)
} }

TUpgradeDbMapper gUpgradeDbMapper;
// this code has no bitshares dependencies, and it
// could be moved to fc, if fc ever adds a leveldb dependency
void UpgradeDbIfNecessary(fc::path dir, leveldb::DB* dbase, const char* record_type, size_t record_type_size)
  {
  size_t old_record_type_size = 0;
  std::string old_record_type;
  fc::path record_type_filename = dir / "RECORD_TYPE";
  //if no RECORD_TYPE file exists
  if ( !boost::filesystem::exists( record_type_filename ) )
    { 
    //must be original type for the database
    old_record_type = record_type;
    int last_char = old_record_type.length() - 1;
    //upgradeable record types should always end with version number
    if (!isdigit(old_record_type[last_char]))
      {
      ilog("Database ${db} is not upgradeable",("db",dir.to_native_ansi_path()));
      return;
      }
    //strip version number from current_record_name and append 0 to set old_record_type (e.g. mytype0)
    while (isdigit(old_record_type[last_char]))
      {
      --last_char;
      }
    ++last_char;
    old_record_type[last_char] = '0';
    old_record_type.resize(last_char+1);

    }
  else //read record type from file
    {
    std::ifstream is(record_type_filename.to_native_ansi_path());
    char buffer[120];
    is.getline(buffer,120);
    old_record_type = buffer;
    is >> old_record_type_size;
    }
  if (old_record_type != record_type)
    {
    //check if upgrade function in registry
    auto upgrade_functionI = gUpgradeDbMapper.UpgradeDbFunctionRegistry.find( old_record_type );
    if (upgrade_functionI != gUpgradeDbMapper.UpgradeDbFunctionRegistry.end())
      {
      ilog("Upgrading database ${db} from ${old} to ${new}",("db",dir.to_native_ansi_path())
                                                            ("old",old_record_type)
                                                            ("new",record_type));
      //update database's RECORD_TYPE to new record type name
      std::ofstream os(record_type_filename.to_native_ansi_path());
      os << record_type << std::endl;
      os << sizeof(record_type);
      //upgrade the database using upgrade function
      upgrade_functionI->second(dbase);
      }
    }
  else if (old_record_type_size == 0) //if record type file never created, create it now
    {
    std::ofstream os(record_type_filename.to_native_ansi_path());
      os << record_type << std::endl;
      os << record_type_size;
    }
  else if (old_record_type_size != record_type_size)
    {
    elog("Record type names match, but record sizes do not match!");
    }
  }