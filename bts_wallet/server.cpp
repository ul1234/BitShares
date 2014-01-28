#include "chain_server.hpp"
#include <fc/thread/thread.hpp>

int main( int argc, char** argv )
{
   try {
       chain_server cserv;
       chain_server::config cfg;
       cfg.port = 4567;
       cserv.configure(cfg);
       fc::usleep( fc::seconds( 60*60*24*365 ) );
   } 
   catch ( const fc::exception& e )
   {
     elog( "${e}", ("e",e.to_detail_string() ) );
     return -1;
   }
   ilog( "Exiting normally" );
   return 0;
}
