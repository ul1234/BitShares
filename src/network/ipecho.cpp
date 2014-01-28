#include <fc/network/tcp_socket.hpp>
#include <fc/network/resolve.hpp>
#include <fc/exception/exception.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/log/logger.hpp>

#include <iostream>
#include <sstream>

namespace bts { namespace network {

   fc::ip::address get_external_ip()
   {
      // terrible, but effective hack used to fetch my remote IP
      std::stringstream request;
      request << "GET /plain HTTP/1.1\r\n";
      request << "Host: ipecho.net\r\n\r\nConnection:Close\r\n";
      auto req = request.str();

      ilog("resolve ipecho.net port 80");
      auto endpoints = fc::resolve( "ipecho.net", 80 );
      for( auto itr = endpoints.begin(); itr != endpoints.end(); ++itr )
      {
         try {
            fc::tcp_socket sock;
            sock.connect_to(*itr);
            sock.write( req.c_str(), req.size() );
            std::vector<char> buffer;
            buffer.resize( 1024 );
            size_t r = sock.readsome( buffer.data(), buffer.size() );
            std::string str(buffer.data(), r);
            std::stringstream instr(str);
            std::string line;
            std::getline(instr, line);
 //           std::cerr<<line<<"\n";
            while( line != "\r" )
            {
              std::getline(instr, line);
  //            std::cerr<<line<<"\n";
            }
            std::getline(instr, line);
            std::getline(instr, line);
//            std::cerr<<"IP: "<<line<<"\n";
            ilog("ip line=${line}",("line",line));
            return fc::ip::address(line.substr(0,line.size()-1));
         } 
         catch ( fc::exception& e ) 
         {
            wlog( "${e}", ("e",e.to_detail_string() ) );
            // ignore errors...
         }
      }
      FC_THROW_EXCEPTION( exception, "Unable to connect to ipecho.net" );
   }
 
} } // bts::network
