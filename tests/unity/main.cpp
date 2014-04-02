#include <unity/server.hpp>
#include <unity/messages.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/io/json.hpp>
#include <fc/thread/thread.hpp>
#include <fc/filesystem.hpp>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <bts/address.hpp>



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
      if( !fc::exists( config_file ) )
      {
         unity::server::config default_config;
         default_config.node_config.node_key = fc::ecc::private_key::generate();
         std::ofstream out( argv[1] );
         out << fc::json::to_pretty_string( default_config );
      }
      auto config = fc::json::from_file( config_file ).as<unity::server::config>();

      std::cout<< "server public key: "
               << std::string( bts::address(config.node_config.node_key.get_public_key()) ) 
               << "\n";
     
      unity::server serv;
      serv.configure(config);

      auto random_dev = open("/dev/random", O_RDONLY);

      while( true )
      {
          fc::usleep( fc::microseconds( rand()%20000000 ) );
          std::vector<char> blob( (rand()%1024) + 256 );
          read( random_dev, blob.data(), blob.size() );
          serv.add_blob(blob); 
      }

      return 0;
   } 
   catch ( const fc::exception& e )
   {
      std::cerr<<e.to_detail_string()<<"\n";
   }
   return -1;
}
