#define BOOST_TEST_MODULE BitSharesTest
#include <boost/test/unit_test.hpp>

#include <bts/blockchain/blockchain_wallet.hpp>
#include <bts/blockchain/blockchain_db.hpp>
#include <bts/blockchain/block.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/filesystem.hpp>
#include <fc/io/json.hpp>
#include <fc/log/logger.hpp>
#include <fc/io/raw.hpp>
#include <iostream>
#include <bts/config.hpp>

#include <fstream>
#include <bts/blockchain/blockchain_printer.hpp>

using namespace bts::blockchain;

fc::ecc::private_key test_genesis_private_key()
{
    return fc::ecc::private_key::generate_from_seed( fc::sha256::hash( "genesis", 7 ) );
}

bts::blockchain::trx_block create_test_genesis_block()
{
   bts::blockchain::trx_block b;
   b.version      = 0;
   b.prev         = block_id_type();
   b.block_num    = 0;
   b.total_shares = 100*COIN;
   b.timestamp    = fc::time_point::from_iso_string("20131201T054434");

   signed_transaction coinbase;
   coinbase.version = 0;
   //coinbase.valid_after = 0;
   //coinbase.valid_blocks = 0;

   // TODO: init from PTS here...
   coinbase.outputs.push_back( 
      trx_output( claim_by_signature_output( bts::address(test_genesis_private_key().get_public_key()) ), 100*COIN, asset::bts) );

   b.trxs.emplace_back( std::move(coinbase) );
   b.trx_mroot   = b.calculate_merkle_root();

   return b;
}

BOOST_AUTO_TEST_CASE( pts_address_test )
{
  try {
   bts::pts_address addr( "PijzuuWFBcgeQTt5rQZdMr3L2Ztf2Aum5x" );
   FC_ASSERT( addr.is_valid() );

   auto test_key = fc::ecc::private_key::generate_from_seed( fc::sha256::hash( "Genesis", 7 ) );
   auto test_pub = test_key.get_public_key();
   bts::pts_address test_addr(test_pub);
   std::string test_str(test_addr);

   ilog( "test pts addr ${addr}", ("addr", test_str) );
   bts::pts_address fromstr(test_str);
   FC_ASSERT( test_addr == fromstr );
   FC_ASSERT( test_addr.is_valid() );
  } 
  catch ( const fc::exception& e )
  {
     elog( "${e}", ("e", e.to_detail_string() ) );
     throw;
  }
}



BOOST_AUTO_TEST_CASE( bitshares_wallet_test )
{
   try {
     fc::temp_directory temp_dir;
     bts::blockchain::blockchain_db chain;
     chain.open( temp_dir.path() / "chain" );

     std::ofstream html( "chain.html" );


     auto genesis = create_test_genesis_block();

     ilog( "genesis block: \n${s}", ("s", fc::json::to_pretty_string(genesis) ) );
     chain.push_block( genesis );


     bts::blockchain::wallet  wallet;
     wallet.open( temp_dir.path() / "wallet" );

     // load a private key into the wallet
     wallet.import_key( test_genesis_private_key() );
     ilog("scan chain" );
     wallet.scan_chain( chain );
     ilog("dump" );
     wallet.dump();
     wallet.set_fee_rate( chain.get_fee_rate() );

     auto balance = wallet.get_balance(bts::blockchain::asset::bts);

     auto a1      = wallet.get_new_address();
     auto a2      = wallet.get_new_address();
     auto a3      = wallet.get_new_address();
     auto a4      = wallet.get_new_address();

     wallet.set_stake(chain.get_stake());
                  
     auto trx1    = wallet.transfer( asset(20.0f,asset::bts), a1 );
     wallet.dump();

     std::vector<signed_transaction> trxs;
     trxs.push_back(trx1);

    ilog( "TRX1: ${TRX}", ("TRX",trxs[0]) );
     auto block1 = chain.generate_next_block( trxs );
     chain.push_block( block1 );
     wallet.set_stake(chain.get_stake());

     wallet.scan_chain( chain, block1.block_num );
     wallet.dump();

     auto trx2    = wallet.transfer( asset(90.0,asset::bts), a2 );
     wallet.dump();

     trxs[0] = trx2;
    ilog( "TRX2: ${TRX}", ("TRX",trxs[0]) );
     auto block2 = chain.generate_next_block( trxs );
     chain.push_block( block2 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block2.block_num );
     wallet.dump();

     std::vector<trx_block> blcks;
     for( uint32_t i = 0; i < 10; ++i )
     {
        auto trx2    = wallet.transfer( asset(2.0,asset::bts), wallet.get_new_address() );
        trxs[0] = trx2;
        auto block2 = chain.generate_next_block( trxs );
        chain.push_block( block2 );
        wallet.set_stake(chain.get_stake());
      
        blcks.push_back(block2);
        wallet.scan_chain( chain, block2.block_num );
        wallet.dump();
     }

     auto bid1 = wallet.bid( asset(1.0,asset::bts),  asset(2.0,asset::usd)/asset(1.0,asset::bts) );
     trxs.resize(1);
     trxs[0] = bid1;
     auto block3 = chain.generate_next_block( trxs );
     chain.push_block( block3 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block3.block_num );
     wallet.dump();


     auto short1 = wallet.short_sell( asset(1.0,asset::usd),  asset(2.0,asset::usd)/asset(1.0,asset::bts) );
     trxs.resize(1);
     trxs[0] = short1;
     auto block4 = chain.generate_next_block( trxs );
     chain.push_block( block4 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block4.block_num );
     wallet.dump();

     trxs   = chain.match_orders(); //wallet.transfer( asset(2*COIN,asset::bts), wallet.get_new_address() );
     auto block5 = chain.generate_next_block( trxs );
     chain.push_block( block5 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block5.block_num );
     wallet.dump();


     trxs.resize(1);
     trxs[0] = wallet.cover( asset( .25, asset::usd ) );

     auto block6 = chain.generate_next_block( trxs );
     chain.push_block( block6 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block6.block_num );
     wallet.dump();

     auto bid2 = wallet.bid( asset(1/8.0,asset::usd),  asset(2.0,asset::usd)/asset(1.0,asset::bts) );
     trxs.resize(1);
     trxs[0] = bid2;
     auto block7 = chain.generate_next_block( trxs );
     chain.push_block( block7 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block7.block_num );
     wallet.dump();



     trxs   = chain.match_orders(); 
     auto block8 = chain.generate_next_block( trxs );
     wallet.dump();
     chain.push_block( block8 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block8.block_num );
     wallet.dump();

     auto bid3 = wallet.bid( asset(1.0/8,asset::usd),  asset(3.0,asset::usd)/asset(1.0,asset::bts) );
     trxs.resize(1);
     trxs[0] = bid3;
     auto block9 = chain.generate_next_block( trxs );
     chain.push_block( block9 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block9.block_num );
     wallet.dump();

     trxs   = chain.match_orders(); 
     auto block10 = chain.generate_next_block( trxs );
     wallet.dump();
     chain.push_block( block10 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block10.block_num );
     wallet.dump();


     auto bid4 = wallet.bid( asset(1.0/16,asset::usd),  asset(3.0,asset::usd)/asset(1.0,asset::bts) );
     auto bid7 = wallet.bid( asset(1.0/7,asset::usd),  asset(3.3,asset::usd)/asset(1.0,asset::bts) );
     ilog( "bid4: ${bid4}", ("bid4",bid4) );
     auto bid5 = wallet.bid( asset(.2,asset::bts),  asset(2.5,asset::usd)/asset(1.0,asset::bts) );
     auto bid6 = wallet.bid( asset(.33,asset::bts),  asset(4.0,asset::usd)/asset(1.0,asset::bts) );
     trxs.resize(4);
     trxs[0] = bid4;
     trxs[1] = bid5;
     trxs[2] = bid6;
     trxs[3] = bid7;
     auto block11 = chain.generate_next_block( trxs );
     chain.push_block( block11 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block11.block_num );
     wallet.dump();

     trxs   = chain.match_orders(); 
     auto block12 = chain.generate_next_block( trxs );
     wallet.dump();
     chain.push_block( block12 );
     wallet.set_stake(chain.get_stake());
     wallet.scan_chain( chain, block12.block_num );
     wallet.dump();


     html << bts::blockchain::pretty_print( genesis, chain );
     html << bts::blockchain::pretty_print( block1, chain );
     html << bts::blockchain::pretty_print( block2, chain );
     std::cerr<< fc::json::to_pretty_string( block1 );
     for( uint32_t i = 0; i < blcks.size(); ++i )
     {
        html << bts::blockchain::pretty_print( blcks[i], chain );
     }
     html << bts::blockchain::pretty_print( block3, chain );
     html << bts::blockchain::pretty_print( block4, chain );
     html << bts::blockchain::pretty_print( block5, chain );
     html << bts::blockchain::pretty_print( block6, chain );
     html << bts::blockchain::pretty_print( block7, chain );
     html << bts::blockchain::pretty_print( block8, chain );
     html << bts::blockchain::pretty_print( block9, chain );
     html << bts::blockchain::pretty_print( block10, chain );
     html << bts::blockchain::pretty_print( block11, chain );
     html << bts::blockchain::pretty_print( block12, chain );

   //  wallet.scan_chain( chain, block2.block_num );
     wallet.dump();


   //  auto trx2    = wallet.transfer( 2000*COIN, asset::bts, a2 );
   //  auto trx3    = wallet.transfer( 3000*COIN, asset::bts, a3 );
   //  auto trx4    = wallet.transfer( 4000*COIN, asset::bts, a4 );
  } 
  catch ( const fc::exception& e )
  {
     elog( "${e}", ("e", e.to_detail_string() ) );
     throw;
  }
}
