#include <bts/blockchain/trx_validation_state.hpp>
#include <bts/config.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/io/raw.hpp>
#include <limits>

#include <fc/log/logger.hpp>

namespace bts  { namespace blockchain { 

trx_validation_state::trx_validation_state( const signed_transaction& t, blockchain_db* d, bool enf, uint32_t h )
:trx(t),balance_sheet( asset::count ),db(d),enforce_unspent(enf),ref_head(h)
{ 
  inputs  = d->fetch_inputs( t.inputs, ref_head );
  if( ref_head == std::numeric_limits<uint32_t>::max()  )
  {
    ref_head = d->head_block_num();
  }

  for( auto i = 0; i < asset::count; ++i )
  {
    balance_sheet[i].in.unit          = (asset::type)i;
    balance_sheet[i].neg_in.unit      = (asset::type)i;
    balance_sheet[i].collat_in.unit   = (asset::bts);

    balance_sheet[i].out.unit         = (asset::type)i;
    balance_sheet[i].collat_out.unit  = (asset::bts);
    balance_sheet[i].neg_out.unit     = (asset::type)i;
  }
  signed_addresses = t.get_signed_addresses();
}

void trx_validation_state::validate()
{
  try
  {
     FC_ASSERT( trx.inputs.size() == inputs.size() );
     
     if( enforce_unspent )
     {
       for( uint32_t i = 0; i < inputs.size(); ++i )
       {
          if( inputs[i].meta_output.is_spent() )
          {
             FC_THROW_EXCEPTION( exception, 
                "input [${iidx}] = references output which was already spent",
                ("iidx",i)("input",trx.inputs[i])("output",inputs[i]) );
          }
       }
     }
     
     for( uint32_t i = 0; i < inputs.size(); ++i )
     {
       try {
         validate_input( inputs[i] ); 
       } FC_RETHROW_EXCEPTIONS( warn, "error validating input ${i}", ("i",i) );
     }

     for( uint32_t i = 0; i < trx.outputs.size(); ++i )
     {
       try {
         validate_output( trx.outputs[i] ); 
       } FC_RETHROW_EXCEPTIONS( warn, "error validating output ${i}", ("i",i) );
     }
     
     for( uint32_t i = 1; i < balance_sheet.size(); ++i )
     {
        if( balance_sheet[i].creates_money() )
        {
            FC_THROW_EXCEPTION( exception, "input value ${in} does not match output value ${out}",
                               ("in", std::string(balance_sheet[i].in))( "out", std::string(balance_sheet[i].out) ) );
                           
        }
     }

     if( !signed_addresses.size() )
     {
        signed_addresses =  trx.get_signed_addresses();
     }
     std::vector<address> missing;
     for( auto itr  = required_sigs.begin(); itr != required_sigs.end(); ++itr )
     {
        if( signed_addresses.find( *itr ) == signed_addresses.end() )
        {
           missing.push_back( *itr );
        }
     }
     if( missing.size() )
     {
        FC_THROW_EXCEPTION( exception, "missing signatures for ${addresses}", ("addresses", missing) );
     }

     // TODO: what should we do about trxs that include extra, unnecessary signatures
     // I cannot just compare required sigs to actual sigs because some trx such as
     // multisig, escrow, etc may optionally include N of M signatures.  Somewhere I should
     // count the total sigs required and then compare to actual number of sigs provided to
     // serve as the upper limit

  } FC_RETHROW_EXCEPTIONS( warn, "error validating transaction", ("state", *this)  );

} // validate 


void trx_validation_state::validate_input( const meta_trx_input& in )
{
     switch( in.output.claim_func )
     {
        case claim_by_signature:
          validate_signature( in );
          return;
        case claim_by_bid:
          validate_bid( in );
          return;
        case claim_by_long:
          validate_long( in );
          return;
        case claim_by_cover:
          validate_cover( in );
          return;
        case claim_by_opt_execute:
          validate_opt( in );
          return;
        case claim_by_multi_sig:
          validate_multi_sig( in );
          return;
        case claim_by_escrow:
          validate_escrow( in );
          return;
        case claim_by_password:
          validate_password( in );
          return;
        default:
          FC_THROW_EXCEPTION( exception, "unsupported claim function ${f}", ("f", in.output.claim_func ) );
     }
} // validate_input


void trx_validation_state::validate_output( const trx_output& out )
{
     FC_ASSERT( out.unit < asset::count );
     FC_ASSERT( out.amount < MAX_BITSHARE_SUPPLY ); // some sanity checks here
     FC_ASSERT( out.amount > 0 );
     switch( out.claim_func )
     {
        case claim_by_signature:
          validate_signature( out );
          return;
        case claim_by_bid:
          validate_bid( out );
          return;
        case claim_by_long:
          validate_long( out );
          return;
        case claim_by_cover:
          validate_cover( out );
          return;
        case claim_by_opt_execute:
          validate_opt( out );
          return;
        case claim_by_multi_sig:
          validate_multi_sig( out );
          return;
        case claim_by_escrow:
          validate_escrow( out );
          return;
        case claim_by_password:
          validate_password( out );
          return;
        default:
          FC_THROW_EXCEPTION( exception, "unsupported claim function ${f}", ("f", out.claim_func ) );
     }
} // validate_output

void trx_validation_state::validate_signature( const trx_output& o )
{
   auto cbs = o.as<claim_by_signature_output>();
   ilog( "${cbs}", ("cbs",cbs));
   FC_ASSERT( cbs.owner != address() );
   asset out(o.amount,o.unit);

   balance_sheet[(asset::type)o.unit].out += out;
   
}
void trx_validation_state::validate_bid( const trx_output& o )
{
   auto bid = o.as<claim_by_bid_output>();
   FC_ASSERT( bid.ask_price.ratio != fc::uint128(0) );
   FC_ASSERT( bid.pay_address != address() );
   FC_ASSERT( bid.ask_price.base_unit == o.unit ||
              bid.ask_price.quote_unit == o.unit );
   FC_ASSERT( bid.ask_price.base_unit != bid.ask_price.quote_unit );
   FC_ASSERT( bid.ask_price.base_unit.value < bid.ask_price.quote_unit.value );

   balance_sheet[(asset::type)o.unit].out += asset(o.amount,o.unit);
}
void trx_validation_state::validate_long( const trx_output& o )
{
   auto long_claim = o.as<claim_by_long_output>();
   FC_ASSERT( long_claim.ask_price.ratio != fc::uint128(0) );
   FC_ASSERT( long_claim.ask_price.base_unit != long_claim.ask_price.quote_unit );
   FC_ASSERT( long_claim.ask_price.base_unit.value < long_claim.ask_price.quote_unit.value );

   balance_sheet[(asset::type)o.unit].out += asset(o.amount,o.unit);

}

/**
 *  If there are any inputs that are existing cover positions, then all cover outputs must
 *  be at the same margin level or higher.   If a user would like to reduce their margin
 *  they must completely cover and go short again.  Otherwise we would require the global
 *  price of the asset to determine whehter or not a margin reduction is allowed.
 *
 */
void trx_validation_state::validate_cover( const trx_output& o )
{ 
   auto cover_claim = o.as<claim_by_cover_output>();
   try {
   auto payoff_unit = (asset::type)cover_claim.payoff_unit;
   balance_sheet[(asset::type)o.unit].out += o.get_amount(); //asset(o.amount,o.unit);
   balance_sheet[payoff_unit].neg_out += cover_claim.get_payoff_amount();
   if( balance_sheet[(asset::type)cover_claim.payoff_unit].collat_in != asset() )
   {
      auto req_price =  balance_sheet[payoff_unit].collat_in / balance_sheet[payoff_unit].neg_in;
      // TODO: verify this should be <= instead of >=
      FC_ASSERT( req_price >= o.get_amount() / cover_claim.get_payoff_amount(), "",
                 ("req_price",req_price)( "amnt", o.get_amount() )( "payoff", cover_claim.get_payoff_amount())("new_price", 
                                                                                                               o.get_amount() / cover_claim.get_payoff_amount() ));
   }
} FC_RETHROW_EXCEPTIONS( warn, "${cover}", ("cover",cover_claim) ) }

void trx_validation_state::validate_opt( const trx_output& o )
{
   auto opt_claim = o.as<claim_by_opt_execute_output>();
}
void trx_validation_state::validate_multi_sig( const trx_output& o )
{
   auto multsig_claim = o.as<claim_by_multi_sig_output>();
}
void trx_validation_state::validate_escrow( const trx_output& o )
{
   auto escrow_claim = o.as<claim_by_escrow_output>();
}
void trx_validation_state::validate_password( const trx_output& o )
{
   auto password_claim = o.as<claim_by_password_output>();
}



/**
 *  Adds the owner to the required signature list
 *  Adds the balance to the trx balance sheet
 *
 *  TODO: this input is also valid if it is 1 year old and an output exists
 *        paying 95% of the balance back to the owner.
 *
 *  TODO: what if the source is an unvested market order... it means the
 *        proceeds of this trx are also 'unvested'.  Perhaps we will have to
 *        propagate the vested state along with the trx, if any inputs are
 *        sourced from an unvested trx, the new trx is also 'unvested' until
 *        the most receint input is fully vested.
 */
void trx_validation_state::validate_signature( const meta_trx_input& in )
{
   try {
       auto cbs = in.output.as<claim_by_signature_output>();
       ilog( "${cbs}", ("cbs",cbs));
       required_sigs.insert( cbs.owner );

       asset output_bal( in.output.amount, in.output.unit );
       balance_sheet[(asset::type)in.output.unit].in += output_bal;
   
   } FC_RETHROW_EXCEPTIONS( warn, "validating signature input ${i}", ("i",in) );
}


/**
 *  A bid input is a valid input in two cases:
 *
 *  1) Signed by owner
 *  2) A suitable output exists in trx that meets the requirements of the bid.
 *       - output paying proper proper asset to proper address at specified exchange rate
 *       - left-over-bid sent to new output with same terms.
 *       - accepted and change bids > min amount
 */
void trx_validation_state::validate_bid( const meta_trx_input& in )
{ try {
    auto cbb = in.output.as<claim_by_bid_output>();
   
    asset output_bal( in.output.amount, in.output.unit );
    balance_sheet[(asset::type)in.output.unit].in += output_bal;

    wlog( "      *** SIGNED BY ***     \n ${signed} \n ", ("signed", signed_addresses) );

    // if the pay address has signed the trx, then that means this is a cancel request
    if( signed_addresses.find( cbb.pay_address ) != signed_addresses.end() )
    {
       //balance_sheet[asset::bts].in += output_bal; 

       balance_sheet[uint8_t(in.output.unit)].in += output_bal;  
    }
    else // someone else accepted the offer based upon the terms of the bid.
    {
        wlog( "      *** SIGNED BY ***     \n ${signed} \n ", ("signed", signed_addresses) );

       // some orders may be split and thus result in
       // two outputs being generated... look for the split order first, then look
       // for the change!  Easy peesy..
       uint16_t split_order = find_unused_bid_output( cbb );
       if( split_order == output_not_found ) // must be a full order...
       {
         uint16_t sig_out   = find_unused_sig_output( cbb.pay_address, output_bal * cbb.ask_price  );
         FC_ASSERT( sig_out != output_not_found, " unable to find payment of ${asset} to ${pay_addr}", ("asset", output_bal*cbb.ask_price)("pay_addr",cbb.pay_address)("in",in) );
         mark_output_as_used( sig_out );
       }
       else // look for change, must be a partial order
       {
         mark_output_as_used( split_order );
         const trx_output& split_out = trx.outputs[split_order];
         auto split_claim = split_out.as<claim_by_bid_output>();
         ilog( "in  bid: ${claim} in: ${in}", ( "claim", cbb)("in",in) );
         ilog( "split bid: ${claim}", ( "claim", split_claim) );


         FC_ASSERT( split_out.amount                      >= cbb.min_trade );
         FC_ASSERT( (in.output.amount - split_out.amount) >= cbb.min_trade );
         FC_ASSERT( split_out.unit   == in.output.unit                     );
         
         // the balance of the order that was accepted
         asset accepted_bal = asset( in.output.amount - split_out.amount, split_out.unit ) * cbb.ask_price; 

         // get balance of partial order, validate that it is greater than min_trade 
         // subtract partial order from output_bal and insure the remaining order is greater than min_trade
         // look for an output making payment of the balance to the pay address
         FC_ASSERT( accepted_bal.amount > 0 )
         uint16_t sig_out   = find_unused_sig_output( cbb.pay_address, accepted_bal /* cbb.ask_price*/ );
         FC_ASSERT( sig_out != output_not_found );
         mark_output_as_used( sig_out );
       }
    }
    
} FC_RETHROW_EXCEPTIONS( warn, "validating bid input ${i}", ("i",in) ) }

/**
 *  Someone offering to go 'short' created an output that could be claimed
 *  by going long.   When taken as an input the output set must contain an
 *  unused cover output, along with the 
 */
void trx_validation_state::validate_long( const meta_trx_input& in )
{ try {
    auto long_claim = in.output.as<claim_by_long_output>();
    asset output_bal( in.output.amount, in.output.unit );
    balance_sheet[(asset::type)in.output.unit].in += output_bal;
    
    if( signed_addresses.find( long_claim.pay_address ) != signed_addresses.end() )
    {
        // canceled orders can reclaim their dividends (assuming the order has been open long enough)
        //balance_sheet[asset::bts].in += output_bal;
       balance_sheet[uint8_t(in.output.unit)].in += output_bal;  
    }
    else // someone else accepted the offer based on terms of the long
    {
       uint16_t split_order = find_unused_long_output( long_claim );
       if( split_order == output_not_found ) // must be a full order...
       {
         uint16_t sig_out   = find_unused_cover_output( claim_by_cover_output( output_bal * long_claim.ask_price, long_claim.pay_address ), 2*in.output.amount ); 
         FC_ASSERT( sig_out != output_not_found, " unable to find cover position of ${asset} to ${pay_addr} with collateral ${collat}", 
                    ("asset", output_bal*long_claim.ask_price)("pay_addr",long_claim.pay_address)("in",in)( "collat",output_bal) );
         mark_output_as_used( sig_out );
       }
       else // look for change
       {
         mark_output_as_used( split_order );
         const trx_output& split_out = trx.outputs[split_order];
         auto split_claim = split_out.as<claim_by_long_output>();
         ilog( "in  bid: ${claim} in: ${in}", ( "claim", long_claim)("in",in) );
         ilog( "split bid: ${claim}", ( "claim", split_claim) );


         FC_ASSERT( split_out.amount                      >= long_claim.min_trade );
         FC_ASSERT( split_out.amount                      <= in.output.amount );
         FC_ASSERT( (in.output.amount - split_out.amount) >= long_claim.min_trade );
         FC_ASSERT( split_out.unit   == in.output.unit                     );
         
         // the balance of the order that was accepted
         asset accepted_bal = asset( in.output.amount - split_out.amount, split_out.unit ) * long_claim.ask_price; 

         // get balance of partial order, validate that it is greater than min_trade 
         // subtract partial order from output_bal and insure the remaining order is greater than min_trade
         // look for an output making payment of the balance to the pay address
         FC_ASSERT( accepted_bal.amount > 0 )
         uint16_t sig_out   = find_unused_cover_output( claim_by_cover_output( accepted_bal, long_claim.pay_address ), 2*(in.output.amount-split_out.amount) );
         FC_ASSERT( sig_out != output_not_found );

         // TODO: verfiy that the collateral is >= 2x input collateral
         mark_output_as_used( sig_out );
       }
    }
} FC_RETHROW_EXCEPTIONS( warn, "", ("in",in) ) } // validate_long

void trx_validation_state::validate_cover( const meta_trx_input& in )
{
   auto cover_in = in.output.as<claim_by_cover_output>();
    
   balance_sheet[(asset::type)in.output.unit].in += in.output.get_amount(); //asset(o.amount,o.unit);
   balance_sheet[(asset::type)cover_in.payoff_unit].neg_in += cover_in.get_payoff_amount();
   // track collateral for payoff unit
   balance_sheet[(asset::type)cover_in.payoff_unit].collat_in += in.output.get_amount();
}

void trx_validation_state::validate_opt( const meta_trx_input& in )
{

}

void trx_validation_state::validate_multi_sig( const meta_trx_input& in )
{
}

void trx_validation_state::validate_escrow( const meta_trx_input& in )
{
}
void trx_validation_state::validate_password( const meta_trx_input& in )
{
}

void trx_validation_state::mark_output_as_used( uint16_t output_number )
{
  FC_ASSERT( output_number != output_not_found );
  FC_ASSERT( used_outputs.insert(output_number).second ); // make sure we don't mark it twice
}

uint16_t trx_validation_state::find_unused_sig_output( const address& owner, const asset& bal )
{ try {
  auto rounded_amount = bal; //asset(bal.get_rounded_amount(),bal.unit);
  ilog( "find unused sig output ${o}  ${bal}", ("o", owner)("bal",bal) );
  for( uint32_t i = 0; i < trx.outputs.size(); ++i )
  {
     if( used_outputs.find(i) == used_outputs.end() )
     {
        ilog( "out: ${i}", ("i",trx.outputs[i]) );
        if( trx.outputs[i].claim_func == claim_by_signature )
        {
           ilog( "amount: ${i} ==? ${r} ", ("i",trx.outputs[i].get_amount())("r",rounded_amount) );
           ilog( "round down amount: ${i} ==? ${r} ", ("i",trx.outputs[i].amount/10)("r",rounded_amount.amount.high_bits()/10) );
           auto delta = int64_t(trx.outputs[i].amount) - int64_t(bal.amount.high_bits());
           ilog( "delta ${d}", ("d",delta) );
           if( abs(delta) < 5  && trx.outputs[i].unit == bal.unit )
           {
              if( trx.outputs[i].as<claim_by_signature_output>().owner == owner )
              {
                 return i;
              }
           }
        }
     }
  }
  return output_not_found;
} FC_RETHROW_EXCEPTIONS( warn, "Unable to find output of ${asset} to ${owner}", ("asset",bal)("owner",owner) ) }

/**
 *  Find a bid that matches the pay_to_address and price, amount may be different because
 *  of partial orders.
 */
uint16_t trx_validation_state::find_unused_bid_output( const claim_by_bid_output& bid_claim )
{
  for( uint32_t i = 0; i < trx.outputs.size(); ++i )
  {
     ilog( "${i} used: ${u}", ("i",i)("u", used_outputs) );
     auto used_out = used_outputs.find(i);
     if( used_out == used_outputs.end() )
     {
        ilog( "out: ${i}", ("i",trx.outputs[i]) );
        if( trx.outputs[i].claim_func == claim_by_bid )
        {
           ilog( "claim by bid ${i} ==? ${e} ", ("i",trx.outputs[i].as<claim_by_bid_output>())("e",bid_claim) );
           if( trx.outputs[i].as<claim_by_bid_output>() == bid_claim )
           {
              ilog( "return found! ${i}", ("i",i) );
              return i;
           }
        }
     }
  }
  return output_not_found;
}

uint16_t trx_validation_state::find_unused_long_output( const claim_by_long_output& long_claim )
{
  for( uint32_t i = 0; i < trx.outputs.size(); ++i )
  {
     ilog( "${i} used: ${u}", ("i",i)("u", used_outputs) );
     auto used_out = used_outputs.find(i);
     if( used_out == used_outputs.end() )
     {
        ilog( "out: ${i}", ("i",trx.outputs[i]) );
        if( trx.outputs[i].claim_func == claim_by_long )
        {
           ilog( "claim by long ${i} ==? ${e} ", ("i",trx.outputs[i].as<claim_by_long_output>())("e",long_claim) );
           if( trx.outputs[i].as<claim_by_long_output>() == long_claim )
           {
              ilog( "return found! ${i}", ("i",i) );
              return i;
           }
        }
     }
  }
  return output_not_found;
}
uint16_t trx_validation_state::find_unused_cover_output( const claim_by_cover_output& cover_claim, uint64_t min_collat )
{
  for( uint32_t i = 0; i < trx.outputs.size(); ++i )
  {
     ilog( "${i} used: ${u}", ("i",i)("u", used_outputs) );
     auto used_out = used_outputs.find(i);
     if( used_out == used_outputs.end() )
     {
        ilog( "out: ${i}", ("i",trx.outputs[i]) );
        if( trx.outputs[i].claim_func == claim_by_cover )
        {
           ilog( "claim by cover ${i} ==? ${e} ", ("i",trx.outputs[i].as<claim_by_cover_output>())("e",cover_claim) );
           if( trx.outputs[i].as<claim_by_cover_output>() == cover_claim && trx.outputs[i].amount >= min_collat ) // TODO: build in some epsilon here?
           {
              ilog( "return found! ${i}", ("i",i) );
              return i;
           }
        }
     }
  }
  return output_not_found;
}


} }  // namespace bts::blockchain
