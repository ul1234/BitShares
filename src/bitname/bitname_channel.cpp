#include <algorithm>
#include <stdint.h>

#include <fc/crypto/sha224.hpp>
#include <bts/bitname/bitname_channel.hpp>
#include <bts/bitname/bitname_messages.hpp>
#include <bts/bitname/bitname_db.hpp>
#include <bts/bitname/bitname_fork_db.hpp>
#include <bts/bitname/bitname_hash.hpp>
#include <bts/blockchain/fork_tree.hpp>
#include <bts/network/server.hpp>
#include <bts/network/channel.hpp>
#include <bts/network/broadcast_manager.hpp>
#include <bts/difficulty.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/thread/thread.hpp>
#include <fc/log/logger.hpp>

#include <unordered_map>

namespace bts { namespace bitname {

  using namespace bts::network;
  namespace detail 
  { 
    class chan_data : public network::channel_data
    {
      public:
        broadcast_manager<name_hash_type,name_header>::channel_data      trxs_mgr;
        broadcast_manager<name_id_type,name_block_index>::channel_data   block_mgr;

        fc::optional<fc::time_point>                                     requested_headers;
        fc::optional<fc::time_point>                                     requested_block;

        /** tracks the block ids this connection has reported to us */
        std::unordered_set<name_id_type>                                 available_blocks;

        /// the head block as reported by the remote node
        name_id_type                                                     recv_head_block_id;

        /// the head block as we have reported to the remote node
        name_id_type                                                     sent_head_block_id;
    };

    struct block_index_download_manager
    {
       name_block                                        incomplete; 
       name_block_index                                  index;
       /** map short id to incomplete.name_trxs index */
       std::unordered_map<short_name_id_type,uint32_t>   unknown;

       bool try_complete( const name_header& n )
       {
         auto itr = unknown.find(n.short_id());
         if( itr != unknown.end() )
         {
            incomplete.name_trxs[itr->second] = n; 
            unknown.erase(itr);
         }
         return unknown.size() == 0;
       }
    };

    struct fetch_loop_state
    {
       bool synchronizing;
    };

    class name_channel_impl : public bts::network::channel
    {
       public:
          name_channel_impl()
          :_delegate(nullptr),_new_block_info(true){}

          name_channel_delegate*                            _delegate;
          /** set this flag anytime the fork database has new info that
           *  might change what blocks to fetch.
           */
          bool                                              _new_block_info; 
          bts::peer::peer_channel_ptr                       _peers;
          network::channel_id                               _chan_id;
                                                            
          name_db                                           _name_db;
          fork_db                                           _fork_db;

          fetch_loop_state                                  _fetch_state;                          
          fc::future<void>                                  _fetch_loop;
           
           // TODO: on connection disconnect, check to see if there was a pending fetch and
           // cancel it so we can get it from someone else.
          fc::optional<fc::time_point>                      _pending_block_fetch;
                                                            
          broadcast_manager<short_name_id_type,name_header> _trx_broadcast_mgr;
          broadcast_manager<name_id_type,name_block_index>  _block_index_broadcast_mgr;

          std::vector<block_index_download_manager>         _block_downloads;

          void fetch_block_from_index( const name_block_index& index )
          {
             block_index_download_manager  block_idx_downloader;
             block_idx_downloader.incomplete = name_block(index.header);
             block_idx_downloader.index      = index;

             block_idx_downloader.incomplete.name_trxs.resize( index.name_trxs.size() );
             for( uint32_t i = 0; i < index.name_trxs.size(); ++i )
             {
                auto val = _trx_broadcast_mgr.get_value( index.name_trxs[i] );
                if( val ) 
                {
                   block_idx_downloader.incomplete.name_trxs[i] = *val;
                }
                else
                {
                   FC_ASSERT( block_idx_downloader.unknown.find(index.name_trxs[i]) ==
                              block_idx_downloader.unknown.end() ); // checks for duplicates
                   block_idx_downloader.unknown[index.name_trxs[i]] = i;
                }
             }

             if( block_idx_downloader.unknown.size() == 0 )
             {
                submit_block( block_idx_downloader.incomplete );
             }
             else
             {
                _block_downloads.push_back( block_idx_downloader );
                fetch_unknown_name_trxs( _block_downloads.back() );
             }
          }

          void fetch_unknown_name_trxs( const block_index_download_manager& dlmgr )
          {
             for( auto itr = dlmgr.unknown.begin(); itr != dlmgr.unknown.end(); ++itr )
             {
                // TODO: fetch missing from various hosts.. 

             }
          }

          void update_block_index_downloads( const name_header& trx )
          {
             for( auto itr = _block_downloads.begin(); itr != _block_downloads.end(); )
             {
               if( itr->try_complete( trx) )
               {
                  try {
                    submit_block( itr->incomplete );
                  } 
                  catch ( fc::exception& e )
                  {
                    // TODO: how do we punish block that sent us this...
                    // what was the reason we couldn't submit it... peraps
                    // it is just too old and another block beat it to the
                    // punch... 
                    wlog( "unable to submit block after download\n${e}", 
                          ("e",e.to_detail_string() ) );
                  }
                  itr = _block_downloads.erase(itr); 
               }
               else
               {
                  ++itr;
               }
             }
          }

          void fetch_next_from_fork_db()
          { try {
              if( _pending_block_fetch && 
                 (fc::time_point::now() - *_pending_block_fetch) < fc::seconds( BITNAME_BLOCK_FETCH_TIMEOUT_SEC ) )
              {
                 return;
              }
              if( _new_block_info )
              {
                  _new_block_info = false;
                  auto valid_head_num = _name_db.head_block_num(); 
                  //ilog( "valid_head_num: ${v}", ("v",valid_head_num) ); 
                  if( valid_head_num >= _fork_db.best_fork_height() )
                  {
                     return;
                  }
                  meta_header next_best = _fork_db.best_fork_fetch_at( valid_head_num + 1);
                  //ilog( "next_best: ${v}", ("v",next_best) ); 
                  //ilog( "head_block_id: ${v}", ("v",_name_db.head_block_id()) ); 

                  while( next_best.prev != _name_db.head_block_id() )
                  {
                     wlog( "pop back!" );
                     _name_db.pop_block();
                     next_best = _fork_db.fetch_header( next_best.prev );
                     ilog( "next_best: ${v}", ("v",next_best) ); 
                  }

                  fc::optional<name_block> next_block = _fork_db.fetch_block( next_best.id() );
                  if( next_block )
                  {
                     try {
                         _name_db.push_block( *next_block );
                     } 
                     catch ( const fc::exception& e )
                     {
                         elog( "error applying block from this fork, this fork must be invalid\n${e}", ( "e", e.to_detail_string() ) );
                         _fork_db.set_valid( next_block->id(), false );
                     }
                     _new_block_info = true; // attempt another block on next call
                  }
                  else
                  {
                     auto cons = _peers->get_connections( _chan_id );
                     if( cons.size() != 0  )
                     {
                         fetch_block_from_best_connection( cons, next_best.id() );
                     }
                  }
              }
          } FC_RETHROW_EXCEPTIONS( warn , "" ) }

          /**
           *  The fetch loop has several modes:
           *    1) synchronize mode.
           *    2) maitenance mode.
           *
           *  In Synchronize mode the client is not conserned with inventory
           *  notices from other nodes.  In fact, other nodes probably shouldn't
           *  bother broadcasting inv notices to us until we have finished sync.
           *
           *  The client stays in synchronize mode until it has determined that it
           *  is on the proper chain.  When a client first connects it sends a request
           *  for new block headers and it will get a response that may include 
           *  a potential chain reorganization though this should be relatively
           *  rare.
           *  
           */
          void fetch_loop()
          {
             try 
             {
                while( !_fetch_loop.canceled() )
                {
                   broadcast_inv();

                   fetch_next_from_fork_db();
                   
                   short_name_id_type trx_query = 0;
                   if( _trx_broadcast_mgr.find_next_query( trx_query ) )
                   {
                      auto cons = _peers->get_connections( _chan_id );
                      fetch_name_from_best_connection( cons, trx_query );
                      _trx_broadcast_mgr.item_queried( trx_query );
                   }
                   
                   name_id_type blk_idx_query;
                   if( _block_index_broadcast_mgr.find_next_query( blk_idx_query ) )
                   {
                      auto cons = _peers->get_connections( _chan_id );
                      fetch_block_idx_from_best_connection( cons, blk_idx_query );
                      _block_index_broadcast_mgr.item_queried( blk_idx_query );
                   }


                   /* By using a random sleep we give other peers the oppotunity to find
                    * out about messages before we pick who to fetch from.
                    * TODO: move constants to config.hpp
                    *
                    * TODO: fetch set your fetch order based upon how many times we have received
                    *        an inv regarding a particular item.
                    *
                    * TODO: make sure we seed rand()
                    */
                   fc::usleep( fc::microseconds( (rand() % 20000) + 100) );
                }
             } 
             catch ( const fc::exception& e )
             {
               elog( "fetch loop threw... something bad happened\n${e}", ("e", e.to_detail_string()) );
               // TODO: bitname will hang if we don't find some way to recover or report this
               // to the user...
             }
          }

          void request_latest_blocks()
          {
              auto cons = _peers->get_connections( _chan_id );
              for( auto c = cons.begin(); c != cons.end(); ++c )
              {
                 request_block_headers( *c );  
              }
          }


          /**
           *  Send any new inventory items that we have received since the last
           *  broadcast to all connections that do not know about the inv item.
           */
          void broadcast_inv()
          { try {
              if( _trx_broadcast_mgr.has_new_since_broadcast() || _block_index_broadcast_mgr.has_new_since_broadcast() )
              {
                 auto cons = _peers->get_connections( _chan_id );
                 if( _trx_broadcast_mgr.has_new_since_broadcast() )
                 {
                   for( auto c = cons.begin(); c != cons.end(); ++c )
                   {
                     name_inv_message inv_msg;
                 
                     chan_data& con_data = get_channel_data( *c );
                     inv_msg.name_trxs = _trx_broadcast_mgr.get_inventory( con_data.trxs_mgr );
                 
                     if( inv_msg.name_trxs.size() )
                     {
                       (*c)->send( network::message(inv_msg,_chan_id) );
                       con_data.trxs_mgr.update_known( inv_msg.name_trxs );
                     }
                   }
                   _trx_broadcast_mgr.set_new_since_broadcast(false);
                 }
                 
                 if( _block_index_broadcast_mgr.has_new_since_broadcast() )
                 {
                   for( auto c = cons.begin(); c != cons.end(); ++c )
                   {
                     block_inv_message inv_msg;
                 
                     chan_data& con_data = get_channel_data( *c );
                     inv_msg.block_ids = _block_index_broadcast_mgr.get_inventory( con_data.block_mgr );
                 
                     if( inv_msg.block_ids.size() )
                     {
                       (*c)->send( network::message(inv_msg,_chan_id) );
                       con_data.block_mgr.update_known( inv_msg.block_ids );
                     }
                   }
                   _block_index_broadcast_mgr.set_new_since_broadcast(false);
                 }
             }
          } FC_RETHROW_EXCEPTIONS( warn, "error broadcasting bitname inventory") } // broadcast_inv


          /**
           *   For any given message id, there are many potential hosts from which it could be fetched.  We
           *   want to distribute the load across all hosts equally and therefore, the best one to fetch from
           *   is the host that we have fetched the least from and that has fetched the most from us.
           */
          void fetch_name_from_best_connection( const std::vector<connection_ptr>& cons, uint64_t id )
          { try {
              ilog( "${id}", ("id",id) );
             // if request is made, move id from unknown_names to requested_msgs 
             // TODO: update this algorithm to be something better. 
             for( uint32_t i = 0; i < cons.size(); ++i )
             {
                 ilog( "con ${i}", ("i",i) );
                 chan_data& chan_data = get_channel_data(cons[i]); 
                 if( chan_data.trxs_mgr.knows( id ) && !chan_data.trxs_mgr.has_pending_request() )
                 {
                    chan_data.trxs_mgr.requested(id);
                    get_name_header_message request( id );
                    ilog( "request ${msg}", ("msg",request) );
                    cons[i]->send( network::message( request, _chan_id ) );
                    return;
                 }
             }
          } FC_RETHROW_EXCEPTIONS( warn, "error fetching name ${name_hash}", ("name_hash",id) ) }

          void fetch_block_from_best_connection( const std::vector<connection_ptr>& cons,  const name_id_type& id )
          { try {
              ilog( "${id}", ("id",id) );
             // if request is made, move id from unknown_names to requested_msgs 
             // TODO: update this algorithm to be something better. 
             for( uint32_t i = 0; i < cons.size(); ++i )
             {
                 ilog( "con ${i}", ("i",i) );
                 chan_data& chan_data = get_channel_data(cons[i]); 
                 if( chan_data.available_blocks.find(id) != chan_data.available_blocks.end() )
                 {
                    ilog( "request ${msg}", ("msg",get_block_message(id)) );
                    _pending_block_fetch = fc::time_point::now();
                    get_channel_data( cons[i] ).requested_block = *_pending_block_fetch;
                    // TODO: track how many blocks I have requested from this connection... 
                    // and perform soem load balancing...
                    cons[i]->send( network::message( get_block_message(id), _chan_id ) );
                    return;
                 }
                 else
                 {
                 }
             }
          } FC_RETHROW_EXCEPTIONS( warn, "error fetching name ${name_hash}", ("name_hash",id) ) }

          void fetch_block_idx_from_best_connection( const std::vector<connection_ptr>& cons,  const name_id_type& id )
          { try {
              ilog( "${id}", ("id",id) );
             // if request is made, move id from unknown_names to requested_msgs 
             // TODO: update this algorithm to be something better. 
             for( uint32_t i = 0; i < cons.size(); ++i )
             {
                 ilog( "con ${i}", ("i",i) );
                 chan_data& chan_data = get_channel_data(cons[i]); 
                 if( chan_data.block_mgr.knows(id) && !chan_data.block_mgr.has_pending_request() )
                 {
                    ilog( "request ${msg}", ("msg",get_block_index_message(id)) );
                    chan_data.block_mgr.requested(id);
                    // TODO: track how many blocks I have requested from this connection... 
                    // and perform soem load balancing...
                    cons[i]->send( network::message( get_block_index_message(id), _chan_id ) );
                    return;
                 }
             }
          } FC_RETHROW_EXCEPTIONS( warn, "error fetching name ${name_hash}", ("name_hash",id) ) }


          /**
           *  Get or create the bitchat channel data for this connection and return
           *  a reference to the result.
           */
          chan_data& get_channel_data( const connection_ptr& c )
          {
              auto cd = c->get_channel_data( _chan_id );
              if( !cd )
              {
                 cd = std::make_shared<chan_data>();
                 c->set_channel_data( _chan_id, cd );
              }
              chan_data& cdat = cd->as<chan_data>();
              return cdat;
          }


          virtual void handle_subscribe( const connection_ptr& c )
          {
              get_channel_data(c); // creates it... 
              request_latest_blocks();
          }

          virtual void handle_unsubscribe( const connection_ptr& c )
          {
              c->set_channel_data( _chan_id, nullptr );
          }

          /* ===================================================== */   
          void handle_message( const connection_ptr& con, const message& m )
          { 
            try {
             chan_data& cdat = get_channel_data(con);
   
             ilog( "${msg_type}", ("msg_type", (bitname::message_type)m.msg_type ) );
             
             switch( (bitname::message_type)m.msg_type )
             {
                 case name_inv_msg:
                   handle_name_inv( con, cdat, m.as<name_inv_message>() );
                   break;
                 case block_inv_msg:
                   handle_block_inv( con, cdat, m.as<block_inv_message>() );
                   break;
                 case get_name_inv_msg:
                   handle_get_name_inv( con, cdat, m.as<get_name_inv_message>() );
                   break;
                 case get_headers_msg:
                   handle_get_headers( con, cdat, m.as<get_headers_message>() );
                   break;
                 case get_block_msg:
                   handle_get_block( con, cdat, m.as<get_block_message>() );
                   break;
                 case get_block_index_msg:
                   handle_get_block_index( con, cdat, m.as<get_block_index_message>() );
                   break;
                 case get_name_header_msg:
                   handle_get_name( con, cdat, m.as<get_name_header_message>() );
                   break;
                 case name_header_msg:
                   handle_name( con, cdat, m.as<name_header_message>() );
                   break;
                 case block_index_msg:
                   handle_block_index( con, cdat, m.as<block_index_message>() );
                   break;
                 case block_msg:
                   handle_block( con, cdat, m.as<block_message>() );
                   break;
                 case headers_msg:
                   handle_headers( con, cdat, m.as<headers_message>() );
                   break;
                 default:
                   FC_THROW_EXCEPTION( fc::exception, "unknown bitname message type ${msg_type}", ("msg_type", m.msg_type ) );
             }
            } 
            catch ( fc::exception& e )
            {
              wlog( "${e}  ${from}", ("e",e.to_detail_string())("from",con->remote_endpoint()) );
            }
          }  // handle_message


          /* ===================================================== 
           *  When a new node connects it must locate the best block chain that extends the
           *  current known chain.  
           **/   
          void request_block_headers( const connection_ptr& con )
          { try {
              ilog( "requesting block headers from ${ep}", ("ep",con->remote_endpoint() ));
              chan_data& cdat = get_channel_data(con);
              if( cdat.requested_headers ) 
                  return;

              get_headers_message  request;
              const std::vector<name_id_type>& ids = _name_db.get_header_ids();
              uint32_t delta = 1;
              for( int32_t i = ids.size() - 1; i >= 0;  )
              {
                 request.locator_hashes.push_back(ids[i]);
                 i -= delta;
                 delta *= 2;
              }
              cdat.requested_headers = fc::time_point::now();
              con->send( network::message(request,_chan_id) );
          } FC_RETHROW_EXCEPTIONS( warn, "") }

          /* ===================================================== */   
          void handle_name_inv( const connection_ptr& con,  chan_data& cdat, const name_inv_message& msg )
          {
              ilog( "inv: ${msg}", ("msg",msg) );
              for( auto itr = msg.name_trxs.begin(); itr != msg.name_trxs.end(); ++itr )
              {
                 _trx_broadcast_mgr.received_inventory_notice( *itr ); 
              }
              cdat.trxs_mgr.update_known( msg.name_trxs );
          }
   
          /* ===================================================== */   
          void handle_block_inv( const connection_ptr& con,  chan_data& cdat, const block_inv_message& msg )
          {
              ilog( "inv: ${msg}", ("msg",msg) );
              for( auto itr = msg.block_ids.begin(); itr != msg.block_ids.end(); ++itr )
              {
                 _block_index_broadcast_mgr.received_inventory_notice( *itr );
              }
              cdat.block_mgr.update_known( msg.block_ids );
          }
   
          /* ===================================================== */   
          void handle_get_name_inv( const connection_ptr& con,  chan_data& cdat, const get_name_inv_message& msg )
          {
              name_inv_message reply;
              reply.name_trxs = _trx_broadcast_mgr.get_inventory( cdat.trxs_mgr );
              cdat.trxs_mgr.update_known( reply.name_trxs );
              con->send( network::message(reply,_chan_id) );
          }
   
          /* ===================================================== */   
          void handle_get_headers( const connection_ptr& con,  chan_data& cdat, const get_headers_message& msg )
          { try {
              // TODO: prevent abuse of this message... only allow it at a limited rate and take notice
              // when the remote node starts abusing it.

              uint32_t start_block = 0;
              for( uint32_t i = 0; i < msg.locator_hashes.size(); ++i )
              {
                try {
                 start_block = _name_db.get_block_num( msg.locator_hashes[i] ); 
                 break;
                } 
                catch ( const fc::exception& e )
                {
                  // TODO: should I do something other than log this exception?
                  wlog( "apparently this node is on a different fork, error fetching ${id}\n${e}", 
                        ("id", msg.locator_hashes[i] )("e",e.to_detail_string()) );
                }
              }

              const std::vector<name_id_type>& ids = _name_db.get_header_ids();
              uint32_t end = std::min<uint32_t>(start_block+2000, ids.size() );

              headers_message         reply;
              reply.first_block_num = start_block;
              reply.first = _name_db.fetch_block_header(start_block);
              reply.headers.reserve( end - start_block - 1 );
              for( auto i = start_block+1; i < end; ++i )
              {
                reply.headers.push_back( _name_db.fetch_block_header(ids[i]) );
              }
              reply.head_block_num = ids.size() - 1;
              reply.head_block_id  = ids.back();
              con->send( network::message( reply, _chan_id ) );

          } FC_RETHROW_EXCEPTIONS( warn, "", ("msg",msg) ) }

          /* ===================================================== */   
          void handle_get_block_index( const connection_ptr& con,  chan_data& cdat, const get_block_index_message& msg )
          { try {
             ilog( "${msg}", ("msg",msg) );
             const fc::optional<name_block_index>& trx = _block_index_broadcast_mgr.get_value( msg.block_id );
             if( !trx ) // must be a db
             {
               auto debug_str = _block_index_broadcast_mgr.debug();
               FC_ASSERT( !"Name block index not in broadcast cache", "${str}", ("str",debug_str) );
             }
             con->send( network::message( block_index_message( *trx ), _chan_id ) );
          } FC_RETHROW_EXCEPTIONS( warn, "", ("msg",msg) ) }
   

          /* ===================================================== */   
          void handle_get_block( const connection_ptr& con,  chan_data& cdat, const get_block_message& msg )
          { try {
              // TODO: charge POW for this...
              auto block = _name_db.fetch_block( msg.block_id );
              con->send( network::message( block_message( std::move(block) ), _chan_id ) );
          } FC_RETHROW_EXCEPTIONS( warn, "", ("msg",msg) ) }
   
          /* ===================================================== */   
          void handle_get_name( const connection_ptr& con,  chan_data& cdat, const get_name_header_message& msg )
          {
             ilog( "${msg}", ("msg",msg) );
             const fc::optional<name_header>& trx = _trx_broadcast_mgr.get_value( msg.name_trx_id );
             if( !trx ) // must be a db
             {
               auto debug_str = _trx_broadcast_mgr.debug();
               FC_ASSERT( !"Name transaction not in broadcast cache", "${str}", ("str",debug_str) );
              /*
                ... we should not allow fetching of individual name trx from our db...
                this would require a huge index
                name_header trx = _name_db.fetch_trx_header( msg.name_trx_id );
                con->send( network::message( name_header_message( trx ), _chan_id ) );
              */
             }
             else
             {
                con->send( network::message( name_header_message( *trx ), _chan_id ) );
             }
          }
   
          void handle_block_index( const connection_ptr& con,  chan_data& cdat, const block_index_message& msg )
          {
             ilog( "${msg}", ("msg",msg) );
             cdat.block_mgr.received_response( msg.index.header.id() );

             _fork_db.cache_header( msg.index.header );
             _new_block_info = true;

             if( msg.index.name_trxs.size() == 0 )
             {
                submit_block( msg.index.header );
             }
             else
             {
                _block_downloads.push_back( block_index_download_manager() );
                block_index_download_manager& dlmgr = _block_downloads.back();
                dlmgr.incomplete = name_block(msg.index.header);
                dlmgr.index      = msg.index;
                dlmgr.incomplete.name_trxs.resize( msg.index.name_trxs.size() );

                for( uint32_t i = 0; i < msg.index.name_trxs.size(); ++i )
                {
                    auto opt_trx = _trx_broadcast_mgr.get_value( msg.index.name_trxs[i] );                    
                    if( opt_trx )
                    {
                       dlmgr.incomplete.name_trxs[i] = *opt_trx;
                    }
                    else
                    {
                       dlmgr.unknown[msg.index.name_trxs[i]] = i;
                       _trx_broadcast_mgr.received_inventory_notice( msg.index.name_trxs[i] ); 
                       cdat.trxs_mgr.update_known( msg.index.name_trxs[i] );
                    }
                }
                if( dlmgr.unknown.size() == 0 )
                {
                    submit_block( dlmgr.incomplete );
                    _block_downloads.pop_back();
                }
             }
          }


          void handle_name( const connection_ptr& con,  chan_data& cdat, const name_header_message& msg )
          { try {
             ilog( "${msg}", ("msg",msg) );
             auto short_id = msg.trx.short_id();
             cdat.trxs_mgr.received_response( short_id );
             try { 
                // attempt to complete blocks without validating the trx so that
                // we can then mark the block as 'complete' and then invalidate it
                update_block_index_downloads( msg.trx ); 
                submit_name( msg.trx );
             } 
             catch ( fc::exception& )
             {
               // TODO: connection just sent us an invalid trx... what do we do...
               // log it and ignore it because it was probably for the prior
               // block that they haven't received yet...  we should note it though.
               // 
               // it may be valid because we are not yet synced... 
                _trx_broadcast_mgr.validated( short_id, msg.trx, false );
               // FC_RETHROW_EXCEPTION( e, warn, "" );
             }
          } FC_RETHROW_EXCEPTIONS( warn, "", ("msg", msg) ) }

   
          void handle_block( const connection_ptr& con,  chan_data& cdat, const block_message& msg )
          { try {
               FC_ASSERT( !!cdat.requested_block );

               // TODO: make sure that I requested this block... 
               _fork_db.cache_block( msg.block );
               _new_block_info = true;
               cdat.requested_block.reset();
               _pending_block_fetch.reset();
               try {
                  submit_block(msg.block); //_name_db.push_block( msg.block ); 
               } 
               catch( const fc::exception& )
               {
                 // don't try to fetch this or any of its decendants again..
                 //_fork_tree.set_valid_state( _name_db.head_block_num()+1, msg.block.id(), false );
                 throw;
               }
          } FC_RETHROW_EXCEPTIONS( warn,"handling block ${block}", ("block",msg) ) }
   

          /**
           *  Received in response to get_headers message, we should certify that we requested this.
           */
          void handle_headers( const connection_ptr& con,  chan_data& cdat, const headers_message& msg )
          { try {
              FC_ASSERT( !!cdat.requested_headers );
              cdat.requested_headers.reset();
              
              // TODO: validate that all ids reported have the min proof of work for a name.

              ilog( "received ${msg} block headers", ("msg",msg.headers.size() ) );
              _fork_db.cache_header( msg.first );
              _new_block_info = true;
              name_id_type prev_id = msg.first.id();
              for( auto itr = msg.headers.begin(); itr != msg.headers.end(); ++itr )
              {
                 name_header next_head( *itr, prev_id );
                 ilog( "${id} = ${next_head}", ("id",next_head.id())("next_head",next_head) );
                 _fork_db.cache_header( next_head );
                 prev_id = next_head.id();

                 if( prev_id > max_name_hash() )
                 {
                    // then we should disconnect.... 
                    wlog( "node produced name header with insufficient minimum work" );
                    con->close();
                    return;
                 }

                 cdat.available_blocks.insert(prev_id);
              }

              if( prev_id != msg.head_block_id )
              {
                  cdat.requested_headers = fc::time_point::now();
                  get_headers_message  request;
                  request.locator_hashes.push_back( prev_id );
                  con->send( network::message( request, _chan_id ) );
              }
              
          } FC_RETHROW_EXCEPTIONS( warn, "", ("msg",msg) ) } 

          void submit_name( const name_header& new_name_trx )
          { try {
             _name_db.validate_trx( new_name_trx );
             _trx_broadcast_mgr.validated( new_name_trx.short_id(), new_name_trx, true );
             if( _delegate )
             {
               try {
                  _delegate->pending_name_trx( new_name_trx );
               } 
               catch ( const fc::exception& e )
               {
                 // This could fail if the head block was replaced between the start of the last
                 // mining round and the discovery of a name... perhaps catch this earlier rather than
                 // waiting until we get here!
                 wlog( "delegate threw exception... it shouldn't do that!\n ${e}", ("e", e.to_detail_string() ) );
               }
             }
          } FC_RETHROW_EXCEPTIONS( warn, "error submitting name", ("new_name_trx", new_name_trx) ) }

          void submit_block( const name_block& block )
          { try {
             _fork_db.cache_block( block );
             _new_block_info = true;
             _name_db.push_block( block ); // this throws on error
             _name_db.dump(); // DEBUG

             _trx_broadcast_mgr.invalidate_all(); // current inventory is now invalid
             _block_index_broadcast_mgr.clear_old_inventory(); // we can clear old inventory
             _trx_broadcast_mgr.clear_old_inventory(); // this inventory no longer matters
             _block_index_broadcast_mgr.validated( block.id(), block, true );

             if( _delegate ) _delegate->name_block_added( block );
          } FC_RETHROW_EXCEPTIONS( warn, "error submitting block", ("block", block) ) }
    };

  } // namespace detail

  name_channel::name_channel( const bts::peer::peer_channel_ptr& n )
  :my( new detail::name_channel_impl() )
  {
     my->_peers = n;
     my->_chan_id = channel_id(network::name_proto,0);
     my->_peers->subscribe_to_channel( my->_chan_id, my );
  }

  name_channel::~name_channel() 
  { 
     my->_peers->unsubscribe_from_channel( my->_chan_id );
     my->_delegate = nullptr;
     try {
        if( my->_fetch_loop.valid() )
        {
            my->_fetch_loop.cancel();
            my->_fetch_loop.wait();
        }
     } 
     catch ( ... ) 
     {
        wlog( "unexpected exception ${e}", ("e", fc::except_str()));
     }
  } 

  void name_channel::configure( const name_channel::config& c )
  {
      fc::create_directories( c.name_db_dir / "forks" );

      my->_name_db.open( c.name_db_dir, true/*create*/ );
      my->_fork_db.open( c.name_db_dir / "forks" , true/*create*/ );

      my->_fetch_loop = fc::async( [=](){ my->fetch_loop(); } );
      // TODO: connect to the network and attempt to download the chain...
      //      *  what if no peers on on the name channel ??  * 
      //         I guess when I do connect to a peer on this channel they will
      //         learn that I am subscribed to this channel... 
  }
  void name_channel::set_delegate( name_channel_delegate* d )
  {
     my->_delegate = d;
  }

  void name_channel::submit_name( const name_header& new_name_trx )
  { 
     my->submit_name( new_name_trx );
  }

  void name_channel::submit_block( const name_block& block_to_submit )
  {
     //make sure the block is not stale (we could have already got a new block before we
     //found this one). If the current head block doesn't match this transaction's previous block,
     //a new block must have been added already.
     fc::sha224 chain_head_id = my->_name_db.head_block_id();
     if (block_to_submit.prev != chain_head_id)
       {
         wlog("DISCARDING STALE BLOCK");
         return;
       }

     auto id = block_to_submit.id();
     uint64_t block_difficulty = bts::difficulty(id);
     //DLNFIX temp debug, recomment
     ilog( "target diff: ${td}  block diff ${bd} prev block:${pb}" , ("td",my->_name_db.target_difficulty())("bd",block_difficulty)("pb",block_to_submit.prev) );
     if( block_difficulty >= my->_name_db.target_difficulty() )
     {
         my->submit_block( block_to_submit );
     }
     else 
     {
         submit_name( block_to_submit ); 
     }
  }

  /**
   *  Performs a lookup in the internal database 
   */
  fc::optional<name_record> name_channel::lookup_name( const std::string& name )
  { try  {
        try {
          name_trx     last_trx = my->_name_db.fetch_trx( name_hash( name ) );
          name_record  name_rec;

          name_rec.last_update = last_trx.utc_sec;
          name_rec.master_key  = last_trx.master_key;
          name_rec.active_key  = last_trx.active_key;
          name_rec.age         = last_trx.age;
          name_rec.repute      = my->_name_db.fetch_repute( name_hash(name) ); //last_trx.repute_points;
          name_rec.revoked     = last_trx.master_key == fc::ecc::public_key_data();
          name_rec.name_hash   = fc::to_hex((char*)&last_trx.name_hash, sizeof(last_trx.name_hash));
          name_rec.name        = name;

          return name_rec;
        }
        catch ( const fc::key_not_found_exception& )
        {
          // expected, convert to null optional, all other errors should be
          // thrown up the chain
        }
        return fc::optional<name_record>();
  } FC_RETHROW_EXCEPTIONS( warn, "name: ${name}", ("name",name) ) }
  uint32_t      name_channel::get_head_block_number()const
  {
    return my->_name_db.head_block_num();
  }
  name_id_type  name_channel::get_head_block_id()const
  {
    return my->_name_db.head_block_id();
  }

  std::vector<name_header>  name_channel::get_pending_name_trxs()const
  {
    return my->_trx_broadcast_mgr.get_inventory_values();
  }

} } // bts::bitname
