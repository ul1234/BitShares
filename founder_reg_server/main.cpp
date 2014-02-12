#include <bts/db/level_map.hpp>
#include <bts/db/upgrade_leveldb.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/network/tcp_socket.hpp>
#include <fc/rpc/json_connection.hpp>
#include <fc/thread/thread.hpp>
#include <fc/filesystem.hpp>
#include <fc/reflect/reflect.hpp>
#include <fc/io/raw.hpp>
#include <fc/exception/exception.hpp>

#include <fc/log/logger.hpp>
#include <fc/log/file_appender.hpp>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <iostream>

#include <boost/algorithm/string.hpp> 

#ifdef WIN32
#include <Windows.h>
#include <wincon.h>
#endif

struct record1
{
    record1() : points(0){}
    record1( std::string k, double p ) : key(k), points(p) {}
    record1( std::string k, std::string public_key, double p) : key(k), points(p), pub_key(public_key) {}

    std::string key; //founderCode
    double    points;
    std::string pub_key;
};

FC_REFLECT( record1, (key)(points)(pub_key) )

//#define RECORD2
#ifndef RECORD2
typedef record1 record;
#else
struct record2
{
    record2() : points(0){}
    record2( std::string k, double p ) : key(k), points(p), new_field(0) {}
    record2( std::string k, std::string public_key, double p) : key(k), points(p), pub_key(public_key), new_field(0) {}
    //convert from record1 to record2
    record2(const record1& r1)
      {
      key = r1.key;
      points = r1.points;
      pub_key = r1.pub_key;
      new_field = 3;
      }

    std::string key; //founderCode
    double    points;
    std::string pub_key;
    int   new_field;
};


FC_REFLECT( record2, (key)(points)(pub_key)(new_field) )
typedef record2 record;
REGISTER_DB_OBJECT(record,1)

/*
namespace ldb = leveldb;
void convert_record1_db(ldb::DB* dbase)
  {
  ldb::Iterator* dbaseI = dbase->NewIterator( ldb::ReadOptions() );
  dbaseI->SeekToFirst();
  //if empty database, do nothing
  if (dbaseI->status().IsNotFound())
    return;
  if (!dbaseI->status().ok())
    FC_THROW_EXCEPTION( exception, "database error: ${msg}", ("msg", dbaseI->status().ToString() ) );
  //convert dbase objects from legacy TypeVersionNum to current Type
  while (dbaseI->Valid())
    {
      ///load old record type
    record1 old_value;
    fc::datastream<const char*> dstream( dbaseI->value().data(), dbaseI->value().size() );
    fc::raw::unpack( dstream, old_value );
    //convert to new record type
    record new_value(old_value);
    auto vec = fc::raw::pack(new_value);
    ldb::Slice value_slice( vec.data(), vec.size() );             
    ldb::Slice key_slice = dbaseI->key();
    auto status = dbase->Put( ldb::WriteOptions(), key_slice, value_slice );
    if( !status.ok() )
      {
      FC_THROW_EXCEPTION( exception, "database error: ${msg}", ("msg", status.ToString() ) );
      }
    dbaseI->Next();
    } //while
  }
*/
#endif 


int main( int argc, char** argv )
{
#ifdef WIN32
  BOOL console_ok = AllocConsole();

  freopen("CONOUT$", "wb", stdout);
  freopen("CONOUT$", "wb", stderr);
  //freopen( "console.txt", "wb", stdout);
  //freopen( "console.txt", "wb", stderr);
  printf("testing stdout\n");
  fprintf(stderr, "testing stderr\n");
#endif

   try {
         fc::tcp_server                           _tcp_serv;

         //maps keyhoteeId -> founderCode,points,publicKey
         bts::db::level_map<std::string,record>   _known_names;
         _known_names.open( "reg_db" );

         #ifdef RECORD2
//         convert_record1_db(_known_names._db.get());
         #endif
         
         if (argc == 3)
         {  //update records in goood dbase with matching records from messy database
            bts::db::level_map<std::string,record>   _messy_names;
            _messy_names.open( "messy_db" );
            //walkthrough all names in messydb, see if it matches record in good db, update good db with record if so
            auto itr = _messy_names.begin();
            while( itr.valid() )
            {
              auto found_itr = _known_names.find( itr.key() );
              if (found_itr.valid())
              {
                auto id_record = itr.value();
                ilog( "${key} => ${value}", ("key",itr.key())("value",id_record));
                _known_names.store( itr.key(), id_record);
              }
              ++itr;
            }
         }
         // TODO: import CSV list of new keyhoteeIds that can be registered
         else if( argc == 2 )
         {
            FC_ASSERT( fc::exists(argv[1]) );
            std::ifstream in(argv[1]);
            std::string line;
            std::getline(in, line);
            int num_commas = std::count(line.begin(), line.end(), ',');
            if (num_commas == 3)
            {
              while( in.good() )
              {
                 std::stringstream ss(line);
                 std::string name; //keyhoteeId
                 std::getline( ss, name, ',' );
                 boost::to_lower(name);
                 std::string key; //founderCode
                 std::getline( ss, key, ',' );
                 std::string points;
                 std::getline( ss, points, ',' );
                 auto itr = _known_names.find( name );
                 if( !itr.valid() )
                 {
                    std::cerr << name << "\t\t" << key << "\t\t'" << points <<"'\n";
                    double pointsd = atof( points.c_str() );
                    _known_names.store( name, record( key, pointsd ) );
                 }
                 std::getline(in, line);
              }
            }
            else if (num_commas >= 5)
            { //update registered keyhoteeIds with public keys sent from web form
              while( in.good() )
              {
                 std::stringstream ss(line);
                 std::string date;
                 std::getline( ss, date, ',' );
                 std::string email;
                 std::getline( ss, email, ',' );

                 std::string name; //keyhoteeId
                 std::getline( ss, name, ',' );
                 boost::to_lower(name);
                 std::string key; //founderCode
                 std::getline( ss, key, ',' );
                 std::string public_key;
                 std::getline( ss, public_key, ',' );

                 auto itr = _known_names.find( name );
                 if( itr.valid() )
                 {
                    auto record_to_update = itr.value();
                    if (!public_key.empty())
                    {
                      record_to_update.pub_key = public_key;
                      if (record_to_update.key == key)
                        _known_names.store( name, record_to_update);
                      else
                        std::cerr << "Founder code mismatch for " << name << std::endl;
                    }
                    else
                    {
                      std::cerr << "Public key empty for " << name << std::endl;
                    }
                 }
                 std::getline(in, line);
              }
            }
            else
            {
            std::cerr << "Invalid file format: file should have 3 or 5+ fields, has " << num_commas << std::endl;
            return 1;
            }
         }
         else //argc != 2
         {
            //configure logger to also write to log file
            fc::file_appender::config ac;
            /** \warning Use wstring to construct log file name since %TEMP% can point to path containing
                native chars.
            */
            ac.filename = "log.txt";
            ac.truncate = false;
            ac.flush    = true;
            fc::logger::get().add_appender( fc::shared_ptr<fc::file_appender>( new fc::file_appender( fc::variant(ac) ) ) );

            int id_count = 0;
            int unregistered_count = 0;
            auto itr = _known_names.begin();
            while( itr.valid() )
            {
              auto id_record = itr.value();
              //ilog( "${key} => ${value}", ("key",itr.key())("value",id_record));
              ilog( "${key}, ${pub_key}, ${points}", ("key",itr.key())("pub_key",id_record.pub_key)("points",id_record.points));
              ++id_count;
              if (id_record.pub_key.empty())
                ++unregistered_count;
              ++itr;
            }
            ilog( "Total Id Count: ${id_count} Unregistered: ${unregistered_count}",("id_count",id_count)("unregistered_count",unregistered_count) );
         }
         _tcp_serv.listen( 3879 );

         //fc::future<void>    _accept_loop_complete = fc::async( [&]() {
             while( true ) //!_accept_loop_complete.canceled() )
             {
                fc::tcp_socket_ptr sock = std::make_shared<fc::tcp_socket>();
                try 
                {
                  _tcp_serv.accept( *sock );
                }
                catch ( const fc::exception& e )
                {
                  elog( "fatal: error opening socket for rpc connection: ${e}", ("e", e.to_detail_string() ) );
                  //exit(1);
                }
             
                auto buf_istream = std::make_shared<fc::buffered_istream>( sock );
                auto buf_ostream = std::make_shared<fc::buffered_ostream>( sock );
             
                auto json_con = std::make_shared<fc::rpc::json_connection>( std::move(buf_istream), std::move(buf_ostream) );
                json_con->add_method( "register_key", [&]( const fc::variants& params ) -> fc::variant 
                {
                    FC_ASSERT( params.size() == 3 );
                    auto name = params[0].as_string();
                    boost::to_lower(name);
                    name = fc::trim(name);
                    auto rec = _known_names.fetch( name );
                    if( rec.key != params[1].as_string() ) //, "Key ${key} != ${expected}", ("key",params[1])("expected",rec.key) );
                    {
                        FC_ASSERT( !"Invalid Key" );
                    }
                    if( !(rec.pub_key.size() == 0 || rec.pub_key == params[2].as_string() ) )
                    {
                      // FC_ASSERT( rec.pub_key.size() == 0 || rec.pub_key == params[2].as_string() );
                      FC_ASSERT( !"Key already Registered" );
                    }
                    rec.pub_key = params[2].as_string();
                    _known_names.store( params[0].as_string(), rec );
                    return fc::variant( rec );
                });

                fc::async( [json_con]{ json_con->exec().wait(); } );
              }
        // }
        // );


         //_accept_loop_complete.wait();
         return 0;
   } 
   catch ( fc::exception& e )
   {
      elog( "${e}", ("e",e.to_detail_string() ) );
   }
}

