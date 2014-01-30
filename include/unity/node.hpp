#pragma once
#include <fc/crypto/ripemd160.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/time.hpp>
#include <fc/reflect/reflect.hpp>
#include <unordered_set>
#include <unordered_map>
#include <bts/address.hpp>

namespace unity 
{
   typedef fc::uint160 id_type;
         
   struct config
   {
       std::vector<bts::address> unique_node_list;
       fc::ecc::private_key      node_key; 
   };

   struct proposal
   {
      proposal():round(0){}
      fc::sha256 digest()const;

      fc::time_point_sec            timestamp;
      uint32_t                      round;
      std::unordered_set<id_type>   items;
   };

   struct signed_proposal : public proposal
   {
      signed_proposal(){}
      signed_proposal( const proposal& p, const fc::ecc::private_key& key );
      bts::address   get_signee_id()const;


      fc::ecc::compact_signature  node_signature;
   };

   namespace detail { class node_impl; }


   /**
    *  @brief provides core unity algorithm abstracted from 
    *         the communication protocol.
    *
    */
   class node 
   {
      public:
         node();
         ~node();

         void             configure( const config& cfg );
         void             set_round( uint32_t round );

         /**
          *  Track items that the local node has an opinion on
          */
         void             set_item_validity( id_type id, bool valid );
                          
         /** 
          * @return true if processing this proposal results in unity
          *         where unity is defined as 100% of outputs with greater
          *         than 70% of the weighted vote.
          */
         bool             process_proposal( const signed_proposal& p );
         signed_proposal  get_current_proposal()const;

         /**
          * Make sure that 70% of proposals agree on the timestamp and
          * that the current proposal has 70% agreement for every item
          * in the set.
          */
         bool             has_unity()const;

         /**
          *  Removes the items in the current proposal from the input set which
          *  triggers the generation of a new proposal from the unaccepted set.
          *
          *  Resets last proposal from all nodes and increments the round.
          */
         void            accept_current_proposal();
      private: 
         std::unique_ptr<detail::node_impl> my;
   };

} // namespace unity

FC_REFLECT( unity::config, (unique_node_list)(node_key) )
FC_REFLECT( unity::proposal, (timestamp)(round)(items) )
FC_REFLECT_DERIVED( unity::signed_proposal, (unity::proposal), (node_signature) )
