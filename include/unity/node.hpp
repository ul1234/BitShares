#pragma once
#include <fc/crypto/ripemd160.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/time.hpp>
#include <fc/reflect/reflect.hpp>
#include <set>
#include <unordered_map>
#include <bts/address.hpp>

namespace unity 
{
   typedef fc::uint160 id_type;
         
   struct config
   {
       std::set<bts::address> unique_node_list;
       fc::ecc::private_key      node_key; 
   };

   struct proposal
   {
      proposal(){}
      fc::sha256 digest()const;

      fc::time_point_sec          timestamp;
      fc::sha256                  prev;
      std::set<id_type>           items;
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
         void             set_prev( const fc::sha256& prev );

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

      private: 
         std::unique_ptr<detail::node_impl> my;
   };

} // namespace unity

FC_REFLECT( unity::config, (unique_node_list)(node_key) )
FC_REFLECT( unity::proposal, (timestamp)(prev)(items) )
FC_REFLECT_DERIVED( unity::signed_proposal, (unity::proposal), (node_signature) )
