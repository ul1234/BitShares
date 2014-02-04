#include <bts/blockchain/blockchain_market_db.hpp>
#include <bts/db/level_pod_map.hpp>
#include <fc/reflect/variant.hpp>

#include <fc/log/logger.hpp>

namespace bts { namespace blockchain {

  namespace detail
  {
     class market_db_impl
     {
        public:
           db::level_pod_map<market_order,uint32_t> _bids;
           db::level_pod_map<market_order,uint32_t> _asks;
           db::level_pod_map<margin_call,uint32_t>  _calls;
     };

  } // namespace detail
  market_order::market_order( const price& p, const output_reference& loc )
  :base_unit(p.base_unit),quote_unit(p.quote_unit),ratio( p.ratio ),location(loc)
  {}

  price market_order::get_price()const
  {
     return price( ratio, base_unit, quote_unit );
  }


  bool operator == ( const market_order& a, const market_order& b )
  {
     return a.ratio == b.ratio &&
            a.location == b.location &&
            a.base_unit == b.base_unit &&
            a.quote_unit == b.quote_unit;
  }
  bool operator < ( const market_order& a, const market_order& b )
  {
     if( a.base_unit.value < b.base_unit.value ) return true;
     if( a.base_unit.value > b.base_unit.value ) return false;
     if( a.quote_unit.value < b.quote_unit.value ) return true;
     if( a.quote_unit.value > b.quote_unit ) return false;
     if( a.ratio < b.ratio ) return true;
     if( a.ratio > b.ratio ) return false;
     return a.location < b.location;
  }


  bool operator < ( const margin_call& a, const margin_call& b )
  {
     if( a.call_price.quote_unit < b.call_price.quote_unit ) return true;
     if( a.call_price.quote_unit > b.call_price.quote_unit ) return false;
     if( a.call_price.ratio > b.call_price.ratio ) return true;
     if( a.call_price.ratio < b.call_price.ratio ) return false;
     return a.location < b.location;
  }
  bool operator == ( const margin_call& a, const margin_call& b )
  {
     return a.call_price.ratio == b.call_price.ratio && a.call_price.quote_unit == b.call_price.quote_unit && b.location == a.location;
  }

  market_db::market_db()
  :my( new detail::market_db_impl() )
  {
  }

  market_db::~market_db()
  {}

  void market_db::open( const fc::path& db_dir )
  { try {
     fc::create_directories( db_dir / "bids" );
     fc::create_directories( db_dir / "asks" );
     fc::create_directories( db_dir / "calls" );

     my->_bids.open( db_dir / "bids" );
     my->_asks.open( db_dir / "asks" );
     my->_calls.open( db_dir / "calls" );
  } FC_RETHROW_EXCEPTIONS( warn, "unable to open market db ${dir}", ("dir",db_dir) ) }

  void market_db::insert_bid( const market_order& m )
  {
     my->_bids.store( m, 0 );
  }
  void market_db::insert_ask( const market_order& m )
  {
     my->_asks.store( m, 0 );
  }
  void market_db::remove_bid( const market_order& m )
  {
     my->_bids.remove(m);
  }
  void market_db::remove_ask( const market_order& m )
  {
     my->_asks.remove(m);
  }
  void market_db::insert_call( const margin_call& c )
  {
     my->_calls.store( c, 0 );
  }
  void market_db::remove_call( const margin_call& c )
  {
     my->_calls.remove( c );
  }

  /** @pre quote > base  */
  fc::optional<market_order> market_db::get_highest_bid( asset::type quote, asset::type base )
  {
    FC_ASSERT( quote > base );
    fc::optional<market_order> highest_bid;

    return highest_bid;
  }
  /** @pre quote > base  */
  fc::optional<market_order> market_db::get_lowest_ask( asset::type quote, asset::type base )
  {
    FC_ASSERT( quote > base );
    fc::optional<market_order> lowest_ask;

    return lowest_ask;
  }

  std::vector<market_order> market_db::get_bids( asset::type quote_unit, asset::type base_unit )const
  {
     FC_ASSERT( quote_unit > base_unit );

     std::vector<market_order> orders;
     market_order mo;
     mo.base_unit  = base_unit;
     mo.quote_unit = quote_unit;

     auto order_itr  = my->_bids.lower_bound( mo );
     while( order_itr.valid() )
     {
        auto order = order_itr.key();
        if( order.quote_unit != quote_unit || order.base_unit != base_unit )
        {
            return orders;
        }
        orders.push_back(order);
        ++order_itr;
     }
     ilog( "order_itr is not valid!" );
     return orders;
  }

  std::vector<margin_call>  market_db::get_calls( price call_price )const
  {
     ilog( "get_calls price: ${p}", ("p",call_price) );
     std::vector<margin_call> calls;

     auto order_itr  = my->_calls.begin();//lower_bound( margin_call( call_price, output_reference() ) );
     while( order_itr.valid() )
     {
        auto call = order_itr.key();
        ilog( "call ${c}", ("c",call) );
        if( call.call_price.quote_unit != call_price.quote_unit )
           return calls;
        if( call.call_price < call_price )
           return calls;
        calls.push_back(call);
        ++order_itr;
     }
     return calls;
  }

  std::vector<market_order> market_db::get_asks( asset::type quote_unit, asset::type base_unit )const
  {
     FC_ASSERT( quote_unit > base_unit );

     std::vector<market_order> orders;
     market_order mo;
     mo.base_unit  = base_unit;
     mo.quote_unit = quote_unit;

     auto order_itr  = my->_asks.lower_bound( mo );
     while( order_itr.valid() )
     {
        auto order = order_itr.key();
        if( order.quote_unit != quote_unit || order.base_unit != base_unit )
        {
            return orders;
        }
        orders.push_back(order);
        ++order_itr;
     }
     ilog( "order_itr is not valid!" );
     return orders;
  }

} } // bts::blockchain
