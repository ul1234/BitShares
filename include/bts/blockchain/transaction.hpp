#pragma once
#include <bts/blockchain/output_reference.hpp>
#include <bts/address.hpp>
#include <bts/blockchain/asset.hpp>
#include <bts/blockchain/outputs.hpp>
#include <bts/units.hpp>
#include <bts/proof_of_work.hpp>
#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/sha224.hpp>
#include <fc/io/varint.hpp>
#include <fc/exception/exception.hpp>


namespace bts { namespace blockchain {


/**
 *  Defines the source of an input used 
 *  as part of a transaction.  If must first
 *  reference an existing unspent output and
 *  then provide the input data required to
 *  cause the claim function to evaluate true.
 */
struct trx_input
{
    trx_input(){}
    trx_input( const output_reference& src )
    :output_ref(src)
    { }

    template<typename InputType>
    trx_input( const InputType& t, const output_reference& src )
    :output_ref(src)
    {
       input_data = fc::raw::pack(t);
    }

    template<typename InputType>
    InputType as()const
    {
       return fc::raw::unpack<InputType>(input_data);
    }

    output_reference   output_ref;
    std::vector<char>  input_data;
};


/**
 *  Base of all trx outputs, derived classes will define the extra
 *  data associated with the claim_func.  The goal is to enable the
 *  output types to be 'fixed size' and thus each output type would
 *  have its own 'memory pool' in the chain state data structure. This
 *  has the added benefit of conserving space, separating bids/asks/
 *  escrow/and normal transfers into different memory segments and
 *  should give better memory performance.   
 */
struct trx_output
{
    template<typename ClaimType>
    trx_output( const ClaimType& t, const asset& a )
    :amount(a)
    {
       claim_func = ClaimType::type;
       claim_data = fc::raw::pack(t);
    }

    template<typename ClaimType>
    ClaimType as()const
    {
       FC_ASSERT( claim_func == ClaimType::type, "", ("claim_func",claim_func)("ClaimType",ClaimType::type) );
       return fc::raw::unpack<ClaimType>(claim_data);
    }

    trx_output(){}

    asset                                       amount;
    claim_type                                  claim_func;
    std::vector<char>                           claim_data;
};

typedef uint160 transaction_id_type;

/**
 *  @brief maps inputs to outputs.
 *
 */
struct transaction
{
   transaction():version(0),stake(0){}
   fc::sha256                   digest()const;

   uint8_t                      version;        ///< trx version number
   uint32_t                     stake;          ///< used for proof of stake, last 8 bytes of block.id()
   fc::time_point_sec           timestamp;      ///< used to future proof, proof-of-stake
   fc::time_point_sec           valid_after;    ///< trx is only valid after a given time
   fc::time_point_sec           valid_until;    ///< trx is only valid until a given time
   std::vector<trx_input>       inputs;
   std::vector<trx_output>      outputs;
};

struct signed_transaction : public transaction
{
    std::unordered_set<address>      get_signed_addresses()const;
    transaction_id_type              id()const;
    void                             sign( const fc::ecc::private_key& k );
    size_t                           size()const;

    std::set<fc::ecc::compact_signature> sigs;
};

} }  // namespace bts::blockchain

namespace fc {
   void to_variant( const bts::blockchain::trx_output& var,  variant& vo );
   void from_variant( const variant& var,  bts::blockchain::trx_output& vo );
};


FC_REFLECT( bts::blockchain::output_reference, (trx_hash)(output_idx) )
FC_REFLECT( bts::blockchain::trx_input, (output_ref)(input_data) )
FC_REFLECT( bts::blockchain::trx_output, (amount)(claim_func)(claim_data) )
FC_REFLECT( bts::blockchain::transaction, (version)(stake)(timestamp)(valid_after)(valid_until)(inputs)(outputs) )
FC_REFLECT_DERIVED( bts::blockchain::signed_transaction, (bts::blockchain::transaction), (sigs) );

