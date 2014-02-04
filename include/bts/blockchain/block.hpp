#pragma once
#include <bts/small_hash.hpp>
#include <bts/blockchain/proof.hpp>
#include <bts/blockchain/transaction.hpp>
#include <bts/blockchain/asset.hpp>
#include <fc/uint128.hpp>

namespace bts { namespace blockchain {

   typedef uint160  block_id_type;

   /**
    *  Light-weight summary of a block that links it to
    *  all prior blocks.  This summary does not contain
    *  the nonce because that information is provided by
    *  the block_proof struct which is a header plus 
    *  proof of work.   
    */
   struct block_header
   {
       block_header()
       :version(0),block_num(-1),next_difficulty(1),total_shares(0),avail_coindays(0),total_cdd(0),noncea(0),nonceb(0){}
      
       block_id_type       id()const;
       /** given the total cdd by this block, calculate the adjusted difficulty */
       uint64_t            get_required_difficulty(uint64_t prev_difficulty, uint64_t prev_avail_cdays)const;
       uint64_t            get_difficulty()const;
       bool                validate_work()const;
      
       uint8_t             version;
       block_id_type       prev;
       uint32_t            block_num;
       fc::time_point_sec  timestamp;       ///< seconds from 1970
       uint64_t            next_difficulty; ///< difficulty for the next block.
       uint64_t            total_shares; 
       uint64_t            avail_coindays;  ///< total coin days available in the network
       uint64_t            total_cdd;       ///< coindays destroyed by this block
       uint160             trx_mroot;       ///< merkle root of trx included in block, required for light client validation
       uint32_t            noncea;          ///< used for proof of work
       uint32_t            nonceb;          ///< used for proof of work
   };

   /**
    * A block complete with the IDs of the transactions included
    * in the block.  This is useful for communicating summaries when
    * the other party already has all of the trxs.
    */
   struct full_block : public block_header 
   {
      full_block( const block_header& b )
      :block_header(b){}
      full_block(){}
      uint160 calculate_merkle_root()const;
      std::vector<uint160>  trx_ids; 
   };

   /**
    *  A block that contains the full transactions rather than
    *  just the IDs of the transactions.
    */
   struct trx_block : public block_header
   {
      trx_block( const block_header& b )
      :block_header(b){}

      trx_block( const full_block& b, std::vector<signed_transaction> trs )
      :block_header(b),trxs( std::move(trs) ){}

      trx_block(){}
      operator full_block()const;
      uint160 calculate_merkle_root()const;
      std::vector<signed_transaction> trxs;
   };
   
   trx_block create_genesis_block();

} } // bts::blockchain

namespace fc 
{
   void to_variant( const bts::blockchain::trx_output& var,  variant& vo );
   void from_variant( const variant& var,  bts::blockchain::trx_output& vo );
}

FC_REFLECT( bts::blockchain::block_header,  (version)(prev)(block_num)(timestamp)(next_difficulty)(total_shares)(avail_coindays)(total_cdd)(trx_mroot)(noncea)(nonceb) )
FC_REFLECT_DERIVED( bts::blockchain::full_block,  (bts::blockchain::block_header),        (trx_ids) )
FC_REFLECT_DERIVED( bts::blockchain::trx_block,   (bts::blockchain::block_header),        (trxs) )

