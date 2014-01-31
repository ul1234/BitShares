#include <unity/node.hpp>
#include <algorithm>
#include <fc/exception/exception.hpp>
#include <fc/io/raw.hpp>
#include <fc/variant.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/log/logger.hpp>

namespace unity 
{
   signed_proposal::signed_proposal( const proposal& p, const fc::ecc::private_key& key )
   :proposal(p)
   {
      node_signature = key.sign_compact( digest() );   
   }

   fc::sha256    proposal::digest()const
   {
      fc::sha256::encoder enc;
      fc::raw::pack( enc, *this );
      return enc.result();
   }

   bts::address   signed_proposal::get_signee_id()const
   {
      return bts::address( fc::ecc::public_key( node_signature, digest() ) );
   }
   namespace detail
   {
        struct proposal_state 
        {
            proposal_state():weight(0){}
            proposal peer_proposal;
            float    weight;
        };
        struct item_state
        {
            item_state():valid(false),weighted_avg(0),count(0){}
            bool     valid;
            float    weighted_avg;
            uint64_t count;
        };

        class node_impl
        {
           public:
              node_impl():_round(0){}

              config _config;
              uint32_t _round;

              /** status of unique items based upon summary of current _peer_proposals and
               *  our local state of which items are valid.
               */ 
              std::unordered_map<id_type,item_state>                _item_states;

              /// last received proposals / states from all nodes
              std::unordered_map<bts::address,proposal_state>       _peer_proposals;
              /// tracks how many nodes vote for each next proposal
              std::unordered_map<fc::sha256,uint32_t>               _next_proposal_votes;
              /// tracks how many nodes vote for each prev proposal
              std::unordered_map<fc::sha256,uint32_t>               _prev_proposal_votes;

              proposal                                              _current_proposal;
              proposal                                              _prev_proposal;


              bool is_new_peer( const bts::address& p )
              {
                 return _peer_proposals.find(p) == _peer_proposals.end();
              }

              void increment_prev_count( const fc::sha256& prev )
              {
                 auto itr = _prev_proposal_votes.find(prev);
                 if( itr != _prev_proposal_votes.end() )
                 {
                    itr->second++;
                 }
                 else
                 {
                    _prev_proposal_votes[prev] = 1;
                 }
              }

              void decrement_prev_count( const fc::sha256& prev )
              {
                 auto itr = _prev_proposal_votes.find(prev);
                 if( itr != _prev_proposal_votes.end() )
                 {
                    if( 0 == --itr->second ) 
                    {
                       _prev_proposal_votes.erase(itr);
                    }
                 }
              }

              void increment_next_count( const fc::sha256& next )
              {
                 auto itr = _next_proposal_votes.find(next);
                 if( itr != _next_proposal_votes.end() )
                 {
                    itr->second++;
                 }
                 else
                 {
                    _next_proposal_votes[next] = 1;
                 }
              }

              void decrement_next_count( const fc::sha256& next )
              {
                 auto itr = _next_proposal_votes.find(next);
                 if( itr != _next_proposal_votes.end() )
                 {
                    if( 0 == --itr->second ) 
                    {
                       _next_proposal_votes.erase(itr);
                    }
                 }
              }

              fc::sha256 find_majority_next()
              {
                  fc::sha256 best;
                  uint32_t   most = 0;
                  for( auto itr = _next_proposal_votes.begin(); itr != _next_proposal_votes.end(); ++itr )
                  {
                     if( itr->second > most )
                     {
                        most = itr->second;
                        best = itr->first;
                     }
                  }
                  if( most > _config.unique_node_list.size() * .60 )
                     return best;
                  return fc::sha256(); // there is no best
              }

              fc::sha256 find_majority_prev()
              {
                  fc::sha256 best;
                  uint32_t   most = 0;
                  for( auto itr = _prev_proposal_votes.begin(); itr != _prev_proposal_votes.end(); ++itr )
                  {
                     if( itr->second > most )
                     {
                        most = itr->second;
                        best = itr->first;
                     }
                  }
                  if( most > _config.unique_node_list.size() * .60 )
                     return best;
                  return fc::sha256(); // there is no best
              }

              bool process_proposal( const signed_proposal& p )
              {
                  auto signee = p.get_signee_id();
                  FC_ASSERT( signee_in_unique_node_list(signee) );

                  if( is_new_peer(signee) )
                  {
                      ilog( "NEW PEER, INCREMENT PREV COUNT" );
                      increment_prev_count( p.prev );
                  }
                  else // old peer with existing state...
                  {
                     ilog( "OLD PEER, INCREMENT PREV COUNT" );
                     const proposal& cur_prop = _peer_proposals[signee].peer_proposal;
                     if( cur_prop.timestamp > p.timestamp )
                     {
                        return false; // this proposal is out of date
                     }
                     if( cur_prop.digest() == p.digest() )
                     {
                        wlog( "nothing changed with this peer.." );
                        return false;  
                     }

                     if( p.prev != cur_prop.prev )
                     {
                        decrement_prev_count( cur_prop.prev );
                        increment_prev_count( p.prev        );
                     }
                     decrement_next_count( cur_prop.digest() );
                     remove_item_votes( cur_prop );
                  }

                  _peer_proposals[signee].peer_proposal = p;
                  add_item_votes( p );
                  increment_next_count( p.digest() );

                  auto majority_prev = find_majority_prev();
                  if( majority_prev != _current_proposal.prev )
                  {
                     if( majority_prev != fc::sha256() )
                     { // then everyone on the network has moved on without us...
                        generate_initial_proposal(majority_prev);
                        return true; // current proposal changed.
                     } // else there is no majority... hold our position
                     return false;
                  }
                  return update_current_proposal();
              }

              bool update_current_proposal()
              {
                  calculate_avg_unity();
                  sum_weighted_votes();
                  return generate_new_proposal();
              }

              void generate_initial_proposal(const fc::sha256& prev)
              {
                 _current_proposal.prev      = prev;
                 _current_proposal.timestamp = fc::time_point::now();
                 for( auto itr = _item_states.begin(); itr != _item_states.end(); ++itr )
                 {
                    if( itr->second.valid )
                    {
                       _current_proposal.items.insert( itr->first );
                    }
                 }
                 ilog( "${id} => ${init}", ("id", _current_proposal.digest())("init",_current_proposal) );
                 // recursive... keep our own proposal on equal footing...
                 // process_proposal(get_current_proposal());
                // _peer_proposals[bts::address(_config.node_key.get_public_key())].peer_proposal = _current_proposal;
              }

              bool signee_in_unique_node_list( const bts::address& id )
              {
                  for( auto itr = _config.unique_node_list.begin(); 
                       itr != _config.unique_node_list.end(); ++itr )
                  {
                     if( *itr == id ) return true;
                  }
                  return false;
              }

              void remove_item_votes( const proposal& p )
              {
                 for( auto itr = p.items.begin(); itr != p.items.end(); ++itr )
                 {
                     auto cur_vote = _item_states.find( *itr );
                     if( cur_vote != _item_states.end() )
                     {
                        if( cur_vote->second.count > 0 ) cur_vote->second.count--;
                     }
                 }
              }
              void add_item_votes( const proposal& p )
              {
                 for( auto itr = p.items.begin(); itr != p.items.end(); ++itr )
                 {
                     auto cur_vote = _item_states.find( *itr );
                     if( cur_vote != _item_states.end() )
                     {
                        cur_vote->second.count++;
                     }
                     else
                     {
                        _item_states[*itr].count = 1;
                     }
                 }
              }

              void calculate_avg_unity()
              {
                 // TODO: give more vots to peer proposals that have already reached consensus.
                 uint64_t active_peers = std::max<uint64_t>( _peer_proposals.size(), _config.unique_node_list.size()/2 );
                 for( auto itr = _peer_proposals.begin(); itr != _peer_proposals.end(); ++itr )
                 {
                    // we only care about proposals that are on the same page as us
                    if( itr->second.peer_proposal.prev == _current_proposal.prev )
                    {
                       uint64_t total_votes = 0;
                       for( auto item_itr  = itr->second.peer_proposal.items.begin(); 
                                 item_itr != itr->second.peer_proposal.items.end(); ++item_itr )
                       {
                          total_votes += _item_states[*item_itr].count;
                       }
                       ilog( "total votes: ${t}     ", ("t",total_votes) );
                       ilog( "peer proposal items ${s}", ("s", itr->second.peer_proposal.items.size() ) );
                       ilog( "active peers ${a}", ("a",active_peers) );
                       itr->second.weight = double(total_votes) / (itr->second.peer_proposal.items.size()*active_peers);
                    }
                 }
              }

              void sum_weighted_votes()
              {
                 // initialize weights... 
                 for( auto item_itr  = _item_states.begin();
                           item_itr != _item_states.end(); ++item_itr )
                 {
                    item_itr->second.weighted_avg = 0;
                 }
                 for( auto itr = _peer_proposals.begin(); itr != _peer_proposals.end(); ++itr )
                 {
                    // we only care about proposals that are on the same page as us
                    if( itr->second.peer_proposal.prev == _current_proposal.prev )
                    {
                       for( auto item_itr  = itr->second.peer_proposal.items.begin(); 
                                 item_itr != itr->second.peer_proposal.items.end(); ++item_itr )
                       {
                          auto item_state_itr = _item_states.find( *item_itr );
                          if( item_state_itr != _item_states.end() )
                             _item_states[*item_itr].weighted_avg += itr->second.weight;
                          else
                             _item_states[*item_itr].weighted_avg = itr->second.weight;
                       }
                    }
                 }
              }

              float calc_max_unity()
              {
                  float max_unity = 0;
                  for( auto itr = _item_states.begin(); itr != _item_states.end(); ++itr )
                  {
                     ilog( "${i}  ${w}", ("i", itr->first)("w",itr->second.weighted_avg) );
                     if( itr->second.weighted_avg > max_unity )
                     {
                        max_unity = itr->second.weighted_avg;
                     }
                  }
                  return max_unity;
              }

              fc::time_point_sec calc_median_time()
              {
                 std::vector<fc::time_point_sec> times;
                 for( auto itr = _peer_proposals.begin(); itr != _peer_proposals.end(); ++itr )
                 {
                    times.push_back(itr->second.peer_proposal.timestamp);
                 }

                 if( times.size() == 0 ) 
                 {
                    return fc::time_point_sec();
                 }

                 size_t med = times.size()/2;
                 std::nth_element( times.begin(), times.begin()+med, times.end() );
                 return times[med];
              }


              /**
               *  If there are no items with > than 50% consensus then include the
               *  top 50% of the items we have...
               *
               *  If there is at least one item with > 50% consensus then only include
               *  items within 20% of the max c
               */
              bool generate_new_proposal()
              {
                  auto old_digest = _current_proposal.digest();
                  _current_proposal.items.clear();
                  float max_unity       = calc_max_unity();
                  float threshold_unity = max_unity * .75;
                  wlog( "max_unity ${max}", ("max",max_unity) );
                  wlog( "threshold_unity ${max}", ("max",threshold_unity) );
                  
                  for( auto itr = _item_states.begin(); itr != _item_states.end(); ++itr )
                  {
                     if( itr->second.weighted_avg > threshold_unity )
                     {
                        // if we don't have the item locally then it doesn't matter
                        // what the weight is.
                        if( true || itr->second.valid ) // TODO: fix this
                        {
                           _current_proposal.items.insert( itr->first );
                        }
                        else
                        {
                           ilog( "we don't have item: ${i}", ("i",itr->first) );
                           // we don't have this item yet... so we cannot
                           // approve it sight unseen.. perhaps we should 
                           // add it to our fetch queue from someone who
                           // has it.
                        }
                     }
                  }
                  _current_proposal.timestamp = calc_median_time();

                  auto new_digest    = _current_proposal.digest();
                  auto majority_next = find_majority_next();
                  if( majority_next == new_digest )
                  {
                     wlog( "EVERYONE AGREES MOVE ALONG ${p}", ("p", _current_proposal) );
                     _prev_proposal = _current_proposal;
                     // these items have been accepted and shouldn't be
                     // considered for the new initial proposal... 
                     remove_accepted_items( _prev_proposal );

                     // generate new initial condition..
                     generate_initial_proposal(majority_next);
                     return true;
                  }
                  
                  if( old_digest != _current_proposal.digest()  )
                  { // something changed
                      wlog( "PROPOSAL CHANGED: ${id} => ${init}", ("id", _current_proposal.digest())("init",_current_proposal) );
                      //_peer_proposals[bts::address(_config.node_key.get_public_key())] = _current_proposal;
                      // recursive... keep our own proposal on equal footing...
                      // process_proposal(get_current_proposal());
                      return true;
                  }
                  ilog( "nothing changed" );
                  return false;
              }

              void remove_accepted_items( const proposal& p )
              {
                 for( auto itr = p.items.begin(); itr != p.items.end(); ++itr )
                 {
                    _item_states.erase(*itr);
                 }
              }
              signed_proposal  get_current_proposal()const
              {
                  return signed_proposal( _current_proposal, _config.node_key );
              }
        };
   }

   node::node()
   :my( new detail::node_impl() ){}

   node::~node()
   {
   }

   void node::configure( const config& cfg )
   {
      my->_config = cfg;
   }

   void node::set_item_validity( id_type id, bool valid )
   {
      my->_item_states[id].valid = valid;
      if( my->_current_proposal.items.size() == 0 )
      {
         my->generate_initial_proposal(my->_current_proposal.prev);
      }
   }

   bool node::process_proposal( const signed_proposal& p )
   { try {
      return my->process_proposal(p);
   } FC_RETHROW_EXCEPTIONS( warn, "", ("proposal",p) ) }


   signed_proposal  node::get_current_proposal()const
   {
      return my->get_current_proposal();
   }


} // namespace unity
