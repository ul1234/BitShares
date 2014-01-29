#include <unity/node.hpp>
#include <algorithm>
#include <fc/exception/exception.hpp>
#include <fc/io/raw.hpp>
#include <fc/variant.hpp>
#include <fc/reflect/variant.hpp>

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

              std::unordered_map<id_type,item_state>           _item_states;
              std::unordered_map<id_type,proposal_state>       _peer_proposals;

              proposal                                         _current_proposal;

              bool signee_in_unique_node_list( const id_type& id )
              {
                  for( auto itr = _config.unique_node_list.begin(); 
                       itr != _config.unique_node_list.end(); ++itr )
                  {
                     if( *itr == id ) return true;
                  }
                  return false;
              }

              void remove_votes( const proposal& p )
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
              void add_votes( const proposal& p )
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
                 uint64_t active_peers = std::max<uint64_t>( _peer_proposals.size(), _config.unique_node_list.size()/2 );
                 for( auto itr = _peer_proposals.begin(); itr != _peer_proposals.end(); ++itr )
                 {
                     uint64_t total_votes = 0;
                     for( auto item_itr  = itr->second.peer_proposal.items.begin(); 
                               item_itr != itr->second.peer_proposal.items.end(); ++item_itr )
                     {
                        total_votes += _item_states[*item_itr].count;
                     }
                     itr->second.weight = double(total_votes) / (itr->second.peer_proposal.items.size()*active_peers);
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
                     for( auto item_itr  = itr->second.peer_proposal.items.begin(); 
                               item_itr != itr->second.peer_proposal.items.end(); ++item_itr )
                     {
                        auto item_state_itr = _item_states.find( *item_itr );
                        if( item_state_itr != _item_states.end() )
                           _item_states[*item_itr].weighted_avg += item_state_itr->second.weighted_avg;
                        else
                           _item_states[*item_itr].weighted_avg = item_state_itr->second.weighted_avg;
                     }
                 }
              }

              float calc_max_unity()
              {
                  float max_unity = 0;
                  for( auto itr = _item_states.begin(); itr != _item_states.end(); ++itr )
                  {
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

                 if( times.size() > 0 ) 
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
              void generate_new_proposal()
              {
                  _current_proposal.items.clear();
                  float max_unity = calc_max_unity();
                  float threshold_unity = max_unity * .75;
                  // include only trx >= the median unity... worst case median unity is
                  // 0 and thus include everything we know... we declare unity when the median
                  // consensus is > 0.70 
                  for( auto itr = _item_states.begin(); itr != _item_states.end(); ++itr )
                  {
                     if( itr->second.weighted_avg > threshold_unity )
                     {
                        _current_proposal.items.insert( itr->first );
                     }
                  }
                  _current_proposal.timestamp = calc_median_time();
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
   void node::set_round( uint32_t round )
   {
      my->_round = round;
   }

   void node::set_item_validity( id_type id, bool valid )
   {
      my->_item_states[id].valid = valid;
   }

   bool node::process_proposal( const signed_proposal& p )
   { try {
      auto signee = p.get_signee_id();
      FC_ASSERT( my->_round == p.round );
      FC_ASSERT( my->signee_in_unique_node_list(signee) );
      
      my->remove_votes( my->_peer_proposals[signee].peer_proposal );
      my->_peer_proposals[signee].peer_proposal = p;
      my->add_votes( my->_peer_proposals[signee].peer_proposal );

      my->calculate_avg_unity();
      my->sum_weighted_votes();
      my->generate_new_proposal();

      return has_unity();
   } FC_RETHROW_EXCEPTIONS( warn, "", ("proposal",p) ) }


   bool node::has_unity()const
   {
       std::unordered_map<uint32_t,uint32_t>  time_votes;
       uint64_t max_votes = 0;
       for( auto itr = my->_peer_proposals.begin(); itr != my->_peer_proposals.end(); ++itr )
       {
          auto time_itr = time_votes.find( itr->second.peer_proposal.timestamp.sec_since_epoch() );
          if( time_itr == time_votes.end() ) 
          {
             time_votes[itr->second.peer_proposal.timestamp.sec_since_epoch()] = 1;
          }
          else
          {
             time_votes[itr->second.peer_proposal.timestamp.sec_since_epoch()]++;
          }
          if( time_votes[itr->second.peer_proposal.timestamp.sec_since_epoch()] > max_votes )
          {
             max_votes =  time_votes[itr->second.peer_proposal.timestamp.sec_since_epoch()];
          }
       }
       if(  double(max_votes) / my->_peer_proposals.size() < 0.70 )
          return false; // we haven't even agreed on the timestamp yet

       return true;
   }

   void node::accept_current_proposal()
   {

   }

   signed_proposal  node::get_current_proposal()const
   {
      return signed_proposal( my->_current_proposal, my->_config.node_key );
   }


} // namespace unity
