#include <bts/blockchain/blockchain_market_db.hpp>
#include <fc/log/logger.hpp>
#include <fc/reflect/variant.hpp>
using namespace bts::blockchain;

int main( int argc, char** argv )
{
   market_db db;
   db.open( "db_test" );

   db.insert_call( margin_call( asset(1.0,asset::usd) / asset( 1.0,asset::bts ), output_reference() )  );
   db.insert_call( margin_call( asset(0.66,asset::usd) / asset( 1.0,asset::bts ), output_reference() )  );
   db.insert_call( margin_call( asset(0.5,asset::usd) / asset( 1.0,asset::bts ), output_reference() )  );
   db.insert_call( margin_call( asset(2.0,asset::usd) / asset( 1.0,asset::bts ), output_reference() )  );

   auto calls = db.get_calls( asset(0.55,asset::usd)/asset(1.0,asset::bts) );
   ilog( "calls: ${calls}", ("calls",calls) );

   return 0;
}
