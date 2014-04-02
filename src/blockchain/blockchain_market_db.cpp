#include <bts/blockchain/blockchain_market_db.hpp>
#include <bts/blockchain/blockchain_db.hpp>
#include <bts/db/level_pod_map.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/log/logger.hpp>

#include <algorithm>

struct price_point_key
{
   bts::blockchain::asset::type quote;
   bts::blockchain::asset::type base;
   fc::time_point_sec           timestamp;

   price_point_key( bts::blockchain::asset::type q, bts::blockchain::asset::type b, fc::time_point_sec t )
   :quote(q),base(b),timestamp(t){}

   friend bool operator < ( const price_point_key& a, const price_point_key& b )
   {
      if( a.quote >= b.quote )         return false;
      if( a.base  >= b.base  )         return false;
      if( a.timestamp >= b.timestamp ) return false;
      return true;
   }

   friend bool operator == ( const price_point_key& a, const price_point_key& b )
   {
      return a.quote == b.quote && a.base == b.base && a.timestamp == b.timestamp;
   }
};

FC_REFLECT( price_point_key, (quote)(base)(timestamp) )

struct depth_stats
{
   depth_stats( uint64_t b = 0,
                uint64_t a = 0 )
   :bid_depth(0),ask_depth(0){}

   uint64_t bid_depth;
   uint64_t ask_depth;
};
FC_REFLECT( depth_stats, (bid_depth)(ask_depth) )

namespace bts { namespace blockchain {

  namespace detail
  {
     class market_db_impl
     {
        public:
           db::level_pod_map<market_order,uint32_t> _bids;
           db::level_pod_map<market_order,uint32_t> _asks;
           db::level_pod_map<margin_call,uint32_t>  _calls;

           db::level_pod_map<price_point_key, price_point> _price_history;

           db::level_pod_map<asset::type,depth_stats> _depth;
     };

  } // namespace detail


  price_point& price_point::operator += ( const price_point& pp )
  {
     quote_volume += pp.quote_volume;
     base_volume  += pp.base_volume;
     if( pp.from_block < from_block )
     {
        open_bid   = pp.open_bid;
        open_ask   = pp.open_ask;
     }
     if( pp.to_block > to_block )
     {
        close_bid = pp.close_bid;
        close_ask = pp.close_ask;
     }
     high_bid   = std::max( pp.high_bid, high_bid );
     low_bid    = std::min( pp.low_bid, low_bid );
     high_ask   = std::max( pp.high_ask, high_ask );
     low_ask    = std::min( pp.low_ask, low_ask );

     from_time  = std::min( pp.from_time, from_time );
     to_time    = std::max( pp.to_time, to_time );
     from_block = std::min( pp.from_block, from_block );
     to_block   = std::max( pp.to_block, to_block );
     return *this;
  }

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
     if( a.call_price.ratio < b.call_price.ratio ) return true;
     if( a.call_price.ratio > b.call_price.ratio ) return false;
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
     fc::create_directories( db_dir / "price_history" );
     fc::create_directories( db_dir / "depth" );

     my->_bids.open( db_dir / "bids" );
     my->_asks.open( db_dir / "asks" );
     my->_calls.open( db_dir / "calls" );
     my->_price_history.open( db_dir / "price_history" );
     my->_depth.open( db_dir / "depth" );
  } FC_RETHROW_EXCEPTIONS( warn, "unable to open market db ${dir}", ("dir",db_dir) ) }

  void market_db::insert_bid( const market_order& m, uint64_t depth )
  {
     if( depth )
     {
        auto itr = my->_depth.find( m.quote_unit );
        if( itr.valid() )
        {
           auto stat = itr.value();
           stat.bid_depth += depth;
           ilog( "insert bid ${b} with depth ${d}", ("b",m)("d",depth) );
           my->_depth.store( m.quote_unit, stat );
        }
        else
        {
           ilog( "insert bid ${b} with depth ${d}", ("b",m)("d",depth) );
           my->_depth.store( m.quote_unit, depth_stats( depth, 0) );
        }
     }
     my->_bids.store( m, 0 );
  }
  void market_db::insert_ask( const market_order& m, uint64_t depth )
  {
     if( depth )
     {
        auto itr = my->_depth.find( m.quote_unit );
        if( itr.valid() )
        {
           auto stat = itr.value();
           stat.ask_depth += depth;
           my->_depth.store( m.quote_unit, stat );
           ilog( "insert ask ${b} with depth ${d}", ("b",m)("d",depth) );
        }
        else
        {
           ilog( "insert ask ${b} with depth ${d}", ("b",m)("d",depth) );
           my->_depth.store( m.quote_unit, depth_stats( 0, depth) );
        }
     }
     my->_asks.store( m, 0 );
  }
  void market_db::remove_bid( const market_order& m, uint64_t depth )
  {
     if( depth )
     {
        auto itr = my->_depth.find( m.quote_unit );
        if( itr.valid() )
        {
           auto stat = itr.value();
           FC_ASSERT( stat.bid_depth >= depth, "", ("stat",stat)("depth",depth) );
           stat.bid_depth -= depth;
           my->_depth.store( m.quote_unit, stat );
        }
     }
     my->_bids.remove(m);
  }
  void market_db::remove_ask( const market_order& m, uint64_t depth )
  {
     if( depth )
     {
        auto itr = my->_depth.find( m.quote_unit );
        if( itr.valid() )
        {
           auto stat = itr.value();
           FC_ASSERT( stat.ask_depth >= depth, "", ("stat",stat)("depth",depth) );
           stat.ask_depth -= depth;
           my->_depth.store( m.quote_unit, stat );
        }
     }
     my->_asks.remove(m);
  }
  void market_db::insert_call( const margin_call& c, uint64_t depth )
  {
     if( depth )
     {
        auto itr = my->_depth.find( c.call_price.quote_unit );
        if( itr.valid() )
        {
           auto stat = itr.value();
           stat.bid_depth += depth;
           my->_depth.store( c.call_price.quote_unit, stat );
        }
        else
        {
           my->_depth.store( c.call_price.quote_unit, depth_stats( depth, 0) );
        }
     }
     my->_calls.store( c, 0 );
  }

  void market_db::remove_call( const margin_call& c, uint64_t depth )
  {
     if( depth )
     {
        auto itr = my->_depth.find( c.call_price.quote_unit );
        if( itr.valid() )
        {
           auto stat = itr.value();
           FC_ASSERT( stat.bid_depth >= depth, "", ("stat",stat)("depth",depth) );
           stat.bid_depth -= depth;
           my->_depth.store( c.call_price.quote_unit, stat );
        }
     }
     my->_calls.remove( c ); // TODO... this side effect is not unwond in 
                             // in the event of an exception..
  }

  uint64_t market_db::get_depth( asset::type quote_unit )
  {
     auto itr = my->_depth.find( quote_unit );
     if( itr.valid() )
     {
        auto stat = itr.value();
        return std::min( stat.bid_depth, stat.ask_depth );
     }
     return 0;
  }

  void market_db::push_price_point( const price_point& pt )
  {
     my->_price_history.store( price_point_key( pt.quote_volume.unit, pt.base_volume.unit, pt.from_time ), pt );
  }
  
  /**
   *  This method returns the price history for a given asset pair for a given range and block granularity. 
   */
  std::vector<price_point> market_db::get_history( asset::type quote, asset::type base, fc::time_point_sec from, fc::time_point_sec to, uint32_t blocks_per_point  )
  {
     std::vector<price_point> points;
     uint32_t blocks_in_point = 0;

     auto point_itr = my->_price_history.lower_bound( price_point_key( quote, base, from ) );
     while( point_itr.valid() )
     {
        auto key = point_itr.key();
        if( key.quote != quote ) return points;
        if( key.base != base   ) return points;
        if( key.timestamp > to ) return points;

        if( blocks_in_point == 0 )
        {
          points.push_back( point_itr.value() );
          ++blocks_in_point;
        }
        else if( blocks_in_point < blocks_per_point )
        {
          points.back() += point_itr.value();
          ++blocks_in_point;
        }
        else
        {
          points.push_back( point_itr.value() );
          blocks_in_point = 1;
        }
     }
     return points;
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

     auto order_itr  = my->_calls.lower_bound( margin_call( call_price, output_reference() ) );
     while( order_itr.valid() )
     {
        auto call = order_itr.key();
        ilog( "call ${c}", ("c",call) );
        if( call.call_price.quote_unit != call_price.quote_unit )
           break;
        if( call.call_price < call_price )
           break;
        calls.push_back(call);
        ++order_itr;
     }
     std::reverse( calls.begin(), calls.end() );
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
