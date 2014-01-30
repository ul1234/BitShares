#include <unity/server.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/io/json.hpp>
#include <fc/thread/thread.hpp>
#include <fc/filesystem.hpp>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>



int main( int argc, char** argv )
{
   try 
   {
      if( argc < 2 )
      {
         std::cerr<<"usage: "<<argv[0]<<" CONFIG\n";
         return -1;
      }
      fc::path config_file = fc::path( std::string(argv[1]) );
      FC_ASSERT( fc::exists( config_file ), "config file does not exist" );
      auto config = fc::json::from_file( config_file ).as<unity::server::config>();
     
      unity::server serv;
      serv.configure(config);

      auto random_dev = open("/dev/random", O_RDONLY);

      while( true )
      {
          fc::usleep( fc::microseconds( rand()%1000000 ) );
          std::vector<char> blob( (rand()%1024) + 256 );
          read( random_dev, blob.data(), blob.size() );
      }

      return 0;
   } 
   catch ( const fc::exception& e )
   {
      std::cerr<<e.to_detail_string()<<"\n";
   }
   return -1;
}
