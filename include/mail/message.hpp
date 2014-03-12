#pragma once
#include <fc/time.hpp>
#include <fc/array.hpp>
#include <fc/io/varint.hpp>
#include <fc/network/ip.hpp>
#include <fc/io/raw.hpp>

namespace mail {

  struct message_header
  {
     uint32_t  size; //number of bytes in message
     uint32_t  type; //type of message, used to properly unpack different msg types, also basis for msg versioning
  };
  #define MAIL_PACKED_MESSAGE_HEADER 8
  #define MAIL_MESSAGE_HEADER_SIZE_FIELD_SIZE 4

//TODO: MSVC is padding message_header, so for now we're packing it before writing it. We could change
//      to uint32_t proto:8, but then we get a problem with FC_REFLECT (&operator doesn't work on bit-fields)
#ifndef WIN32  
  static_assert( sizeof(message_header) == MAIL_PACKED_MESSAGE_HEADER, "message header fields should be tightly packed" );
#endif

  /**
   *  Abstracts the process of packing/unpacking a message for a 
   *  particular channel.
   */
  struct message : public message_header
  {
     std::vector<char> data;

     message(){}

     message( message&& m )
     :message_header(m),data( std::move(m.data) ){}

     message( const message& m )
     :message_header(m),data( m.data ){}

     /**
      *  Assumes that T::type specifies the message type
      */
     template<typename T>
     message( const T& m ) 
     {
        type = T::type;
        data     = fc::raw::pack(m);
        size     = data.size();
     }
    
     /**
      *  Automatically checks the type and deserializes T in the
      *  opposite process from the constructor.
      */
     template<typename T>
     T as()const 
     {
       try {
        FC_ASSERT( type == T::type );
        T tmp;
        if( data.size() )
        {
           fc::datastream<const char*> ds( data.data(), data.size() );
           fc::raw::unpack( ds, tmp );
        }
        else
        {
           // just to make sure that tmp shouldn't have any data
           fc::datastream<const char*> ds( nullptr, 0 );
           fc::raw::unpack( ds, tmp );
        }
        return tmp;
       } FC_RETHROW_EXCEPTIONS( warn, 
            "error unpacking network message as a '${type}'  ${x} != ${type}", 
            ("type", fc::get_typename<T>::name() )
            ("x", T::type)
            ("type", type)
            );
     }
  };


 } // mail


FC_REFLECT( mail::message_header, (size)(type) )
//FC_REFLECT_DERIVED( bts::network::message, (bts::network::message_header), (data) )
