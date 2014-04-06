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
#include <locale>

#include <boost/algorithm/string.hpp> 

#ifdef WIN32
#include <Windows.h>
#include <wincon.h>
#endif

#include <fstream>

std::ofstream deb("/tmp/debug.txt");

struct record0
{
    record0() : points(0){}
    record0( std::string k, double p ) : key(k), points(p) {}
    record0( std::string k, std::string public_key, double p) : key(k), points(p), pub_key(public_key) {}

    std::string key; //founderCode
    double    points;
    std::string pub_key;
};
FC_REFLECT( record0, (key)(points)(pub_key) )

//#define RECORD1
#ifndef RECORD1
typedef record0 record;
REGISTER_DB_OBJECT(record,0)
#else
struct record1
{
    record1() : points(0){}
    record1( std::string k, double p ) : key(k), points(p), new_field(0) {}
    record1( std::string k, std::string public_key, double p) : key(k), points(p), pub_key(public_key), new_field(0) {}
    //convert from record1 to record2
    record1(const record0& r0)
      {
      key = r0.key;
      points = r0.points;
      pub_key = r0.pub_key;
      new_field = 3;
      }

    std::string key; //founderCode
    double    points;
    std::string pub_key;
    int   new_field;
};
FC_REFLECT( record1, (key)(points)(pub_key)(new_field) )

struct record2
{
    record2() : points(0){}
    record2( std::string k, double p ) : key(k), points(p), new_field(0) {}
    record2( std::string k, std::string public_key, double p) : key(k), points(p), pub_key(public_key), new_field(0) {}
    //convert from record1 to record2
    record2(const record1& rec)
      {
      key = rec.key;
      points = rec.points;
      pub_key = rec.pub_key;
      new_field = 3;
      x = y = z = 0.0;
      }

    std::string key; //founderCode
    double    points;
    std::string pub_key;
    int   new_field;
    double x;
    double y;
    double z;
};
FC_REFLECT( record2, (key)(points)(pub_key)(new_field)(x)(y)(z) )


typedef record2 record;
REGISTER_DB_OBJECT(record,0)
REGISTER_DB_OBJECT(record,1)
REGISTER_DB_OBJECT(record,2)
#endif 


bool is_known(bts::db::level_map<std::string,record>& _known_names, std::string name)
{
   auto itr = _known_names.find(name);
   if (itr.valid())
      deb << "  found as " << name << std::endl;
   return itr.valid();
}

void convertToAscii(const std::string& input, std::string* buffer)
{
   buffer->reserve(input.size());
   for (const auto& c : input)
   {
      unsigned int cCode = c;
      if (cCode > 0x7F)
      {
         char numBuffer[64];
         sprintf(numBuffer, "_0x%X_", cCode);
         buffer->append(numBuffer);
      }
      else
      {
         *buffer += toupper(c);
      }
    }
}

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
         auto fix_itr = _known_names.begin();
         while (fix_itr.valid())
         {
            std::string kid = fix_itr.key();
            std::string asciiName;
            convertToAscii(kid,&asciiName);
            if (kid != asciiName)
            {
               auto unchanged_record = fix_itr.value();
               deb << kid << " to " << asciiName << std::endl;
               _known_names.remove(kid);
               _known_names.store(asciiName,unchanged_record);
            }
            ++fix_itr;
         }
         
         if (argc == 3)
         {  //update records in goood dbase with matching records from messy database
            std::cerr << "update records with records from messy database" << std::endl;
            bts::db::level_map<std::string,record>   _messy_names;
            _messy_names.open( "messy_db" );
            //walkthrough all names in messydb, see if it matches record in good db, update good db with public key if so
            auto itr = _messy_names.begin();
            while( itr.valid() )
            {
              auto found_itr = _known_names.find( itr.key() );
              if (found_itr.valid())
              {
                auto id_record = itr.value();
                auto found_record = found_itr.value();
                found_record.pub_key = id_record.pub_key;
                ilog( "${key} => ${value}", ("key",itr.key())("value",found_record));
                _known_names.store( itr.key(), found_record);
              }
              else //report couldn't be found in debug.txt
              {
                 std::string lower_kid = itr.key();
                 boost::to_lower(lower_kid);
                 found_itr = _known_names.find(lower_kid);
                 if (found_itr.valid())
                    deb << "found " << itr.key() << " as " << lower_kid << std::endl;
                 else
                    deb << "missing " << itr.key() << std::endl;
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
            deb << "num_commas=" << num_commas << "\n";
            std::cerr << "num_commas=" << num_commas << "\n";
            if (num_commas == 1)
            { //fix badly transcribed keyhoteeIDs (replace 1st column names with 2nd column names)
              while( in.good() )
              {
                std::stringstream ss(line);

                std::string original_name; //old keyhoteeId
                std::getline( ss, original_name, ',' );
                std::string name;
                convertToAscii(original_name,&name);

                std::string original_new_name; //old keyhoteeId
                std::getline(ss, original_new_name);
                std::string new_name;
                convertToAscii(original_new_name,&new_name);

                try {
                  auto itr = _known_names.find( name );
                  if (itr.valid())
                  {
                      deb << "found " << name << " replacing with " << new_name << std::endl;
                      auto rec = itr.value();
                      rec.key = new_name;
                      _known_names.store( new_name, rec );
                  }
                  else
                  {
                      deb << name << " NOT FOUND when trying to replace" << std::endl;
                  }
                }
                catch (...)
                {
                  deb << "Couldn't find name " << name << std::endl;
                }

              }
              deb << "FINISHED replacing bad KIDs" << std::endl;
              deb.flush();
            }
            else if (num_commas == 2 || num_commas == 3)
            {
              while( in.good() )
              {
                 std::stringstream ss(line);
                 std::string oname; //keyhoteeId
                 std::getline( ss, oname, ',' );
                 std::string name;
                 convertToAscii(oname,&name);
                 //boost::to_lower(name);
                 std::string key; //founderCode
                 std::getline( ss, key, ',' );
                 std::string points;
                 std::getline( ss, points, ',' );
                 deb << "OK"<< std::endl;

                 try {
                 auto itr = _known_names.find( name );
                 if (itr.valid())
                 {
                     deb << "found " << name << std::endl;
                 }
                 else
                 {
                    deb << "adding " << name << "\t\t" << key << "\t\t'" << points << std::endl;
                    double pointsd = atof( points.c_str() );
                    _known_names.store( name, record( key, pointsd ) );
                 }
                 }
                 catch (...)
                 {
                    deb << "Couldn't find name" << std::endl;
                 }
                 std::getline(in, line);
              }
              deb << "FINISHED importing more KIDs" << std::endl;
              deb.flush();
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

                 std::string oname; //keyhoteeId
                 std::getline( ss, oname, ',' );
                 std::string name;
                 convertToAscii(oname,&name);
                 //boost::to_lower(name);
                 std::string key; //founderCode
                 std::getline( ss, key, ',' );
                 std::string public_key;
                 std::getline( ss, public_key, ',' );

                 auto itr = _known_names.find( name );
                 if (!itr.valid())
                 {
                    std::string similar_name = name;
                    boost::to_lower(similar_name);
                    itr = _known_names.find( similar_name );
                    if (!itr.valid())
                    {
                        boost::to_upper(similar_name);
                        itr = _known_names.find( similar_name );
                    }
                 }
                 if( itr.valid() )
                 {
                    auto record_to_update = itr.value();
                    if (!public_key.empty())
                    {
                      record_to_update.pub_key = public_key;
                      if (record_to_update.key == key)
                        _known_names.store( name, record_to_update);
                      else
                        deb << "Founder code mismatch for " << name << std::endl;
                    }
                    else
                    {
                      deb << "Public key empty for " << name << std::endl;
                    }
                 }
                 else
                 {
                    deb << "Looking for " << name << " ";
                    std::string similar_name = name;
                    boost::to_lower(similar_name);
                    if (!is_known(_known_names,similar_name))
                       boost::to_upper(similar_name);
                    if (!is_known(_known_names,similar_name))
                      deb << "NOT FOUND" << std::endl;
                    deb.flush();
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

            std::ofstream report_stream("report.txt");
            int id_count = 0;
            int unregistered_count = 0;
            auto itr = _known_names.begin();
            while( itr.valid() )
            {
              auto id_record = itr.value();
              //ilog( "${key} => ${value}", ("key",itr.key())("value",id_record));
              ilog( "${key}, ${pub_key}, ${p}", ("key",itr.key())("pub_key",id_record.pub_key)("p",id_record.points));
              report_stream << itr.key() << "," << id_record.pub_key << std::endl;
              ++id_count;
              if (id_record.pub_key.empty())
                ++unregistered_count;
              ++itr;
            }
            report_stream.close();
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
                    auto oname = params[0].as_string();
                    oname = fc::trim(oname);
                    std::string name;
                    convertToAscii(oname,&name);

                    auto rec = _known_names.fetch( name );
                    //if a founder code is sent, check it and potentially register the sent public key, else just report back any points
                    if (params[1].as_string().size() != 0)
                    {
                      //ensure founder code is correct
                      if( rec.key != params[1].as_string() ) //, "Key ${key} != ${expected}", ("key",params[1])("expected",rec.key) );
                          FC_ASSERT( !"Invalid Founder Code!" );
                      //report if key is already registered, don't allow re-registering
                      if( !(rec.pub_key.size() == 0 || rec.pub_key == params[2].as_string() ) )
                        FC_ASSERT( !"Different public key already registered!" );
                      //register the public key
                      rec.pub_key = params[2].as_string();
                      bool valid_key = false;
                      if (public_key_address::is_valid(rec.pub_key,&valid_key) && valid_key)
                      {
                        _known_names.store( name, rec );
                      }
                      else
                        FC_ASSERT("Old Keyhotee client");
                    }
                    //if no founder code, then just verify public key matches
                    else if (rec.pub_key != params[2].as_string() )
                      FC_ASSERT( !"Public key mismatch!" );

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

