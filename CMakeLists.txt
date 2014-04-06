# Defines bitshares library target.

project( bitshares )
cmake_minimum_required( VERSION 2.8.12 )

set( CMAKE_AUTOMOC OFF )

add_subdirectory( fc )

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/fc/GitVersionGen")

INCLUDE(GetGitRevisionDescription)

get_git_head_revision(GIT_REFSPEC GIT_SHA2)
get_git_unix_timestamp(GIT_UNIX_TIMESTAMP2)

add_subdirectory( vendor/miniupnp/miniupnpc )


# Set the Berkeley DB version you use
IF (WIN32)
  SET(DB_VERSION 60)
  SET(BDB_STATIC_LIBS 1)
ENDIF()


FIND_PACKAGE( BerkeleyDB )

IF (NOT ${BerkeleyDB_FOUND})
  MESSAGE (SEND_ERROR "Missing required BerkeleyDB package")
ENDIF()

IF(KH_STATIC_QT EQUAL 1)
   # Use dedicated prefix to find static versions of libraries 
   SET(ICU_LIBS_PREFIX "s")
ENDIF()
find_package( ICU )

#include( VersionMacros )
#include( SetupTargetMacros )

IF( WIN32 )
  MESSAGE(STATUS "Configuring Bitshares on WIN32")

  # Set this variable to empty on windows to simplify target_link_libraries specification
  SET(ZLIB_LIBRARIES "")

  add_subdirectory( vendor/leveldb-win )
ELSE(WIN32)
  MESSAGE(STATUS "Configuring Bitshares on UNIX/APPLE")

  FIND_PACKAGE( ZLIB REQUIRED )

  add_subdirectory( vendor/leveldb-1.12.0 )

  # Put here common options for unix & apple platform
  IF(NOT APPLE)
    SET(rt_library rt )
    SET(pthread_library pthread)
  ENDIF(NOT APPLE)

ENDIF(WIN32)

#IF( APPLE )
#FIND_LIBRARY (APPKIT_LIBRARY AppKit) 
#add_subdirectory( vendor/qtmacextras )
#ENDIF( APPLE )

#add_subdirectory( vendor/libzerocoin )

set( sources 
     src/momentum.cpp

     src/db/upgrade_leveldb.cpp

     src/network/stcp_socket.cpp
     src/network/connection.cpp
     src/network/server.cpp
     src/network/get_public_ip.cpp
     src/network/upnp.cpp
     src/network/ipecho.cpp

     src/peer/peer_channel.cpp
     src/peer/peer_messages.cpp

     src/bitname/bitname_block.cpp
     src/bitname/bitname_hash.cpp
     src/bitname/bitname_miner.cpp
     src/bitname/bitname_db.cpp
     src/bitname/bitname_fork_db.cpp
     src/bitname/bitname_messages.cpp
     src/bitname/bitname_channel.cpp
     src/bitname/bitname_client.cpp
     src/bitname/bitname_record.cpp

     src/bitchat/bitchat_private_message.cpp
     src/bitchat/bitchat_messages.cpp
     src/bitchat/bitchat_channel.cpp
     src/bitchat/bitchat_client.cpp 
     src/bitchat/bitchat_message_cache.cpp
     src/bitchat/bitchat_message_db.cpp

     src/mail/mail_connection.cpp
     src/mail/mail_server.cpp
     src/mail/stcp_socket.cpp

     src/addressbook/addressbook.cpp 

     src/blockchain/asset.cpp
     src/blockchain/block.cpp
     src/blockchain/transaction.cpp
     src/blockchain/trx_validation_state.cpp
     src/blockchain/blockchain_outputs.cpp
     src/blockchain/blockchain_db.cpp
     src/blockchain/blockchain_market_db.cpp
     src/blockchain/blockchain_printer.cpp
     src/blockchain/blockchain_messages.cpp
     src/blockchain/blockchain_channel.cpp
     src/blockchain/blockchain_client.cpp
     src/blockchain/blockchain_time_keeper.cpp
     src/blockchain/blockchain_wallet.cpp

     src/rpc/rpc_server.cpp

#  src/unity/node.cpp
#     src/unity/server.cpp
#     src/unity/connection.cpp

     src/application.cpp
     src/difficulty.cpp 
     src/profile.cpp
     src/extended_address.cpp
     src/small_hash.cpp
     src/merkle_tree.cpp
     src/address.cpp
     src/pts_address.cpp
     src/wallet.cpp
     src/keychain.cpp
     src/wallet_cache.cpp
     src/bitcoin_wallet.cpp
     src/electrum_wallet.cpp
     src/multibit_wallet.cpp
     src/armory_wallet.cpp

     vendor/SFMT-src-1.4/SFMT.c
     src/proof_of_work.cpp )

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/GitSHA2.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/GitSHA2.cpp" @ONLY)
list(APPEND sources "${CMAKE_CURRENT_BINARY_DIR}/GitSHA2.cpp" GitSHA2.h)

file(GLOB_RECURSE bitshares_headers include/ *.hpp *.h)
list(APPEND sources ${bitshares_headers})

file(GLOB_RECURSE bitshares_headers src/ *.hpp *.h)
list(APPEND sources ${bitshares_headers})

IF(APPLE)
  SET(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -stdlib=libc++  -Wall" )
ENDIF(APPLE)

# NOT NEEDED !!! fc module has defined its public include dir in its target_include_path and will
# be added automatically to this module include paths!!!
# Otherwise include path is implicitly propagated also to other modules what is a mess
#include_directories( fc/include )
#include_directories( $Boost_INCLUDE_DIR} )

add_library( bshare ${sources} )
target_link_libraries( bshare fc leveldb upnpc-static ${BDB_LIBRARIES} ${ZLIB_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${READLINE_LIBRARIES} ${CMAKE_DL_LIBS})
target_compile_definitions(bshare PRIVATE U_STATIC_IMPLEMENTATION)

# All include directories required to compile dependency headers will be automatically added 
# from dependency list specified in target_link_libraries.
target_include_directories(bshare
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} 
  ${CMAKE_CURRENT_SOURCE_DIR}/vendor/SFMT-src-1.4
  ${CMAKE_CURRENT_SOURCE_DIR}/vendor/miniupnp
  ${BDB_CXX_INCLUDE_DIR}
  ${BDB_INCLUDE_DIR}
  ${ICU_INCLUDE_DIRS}
)

IF(WIN32)
  target_include_directories(bshare
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/leveldb-win/include
  )
  target_compile_definitions(bshare PUBLIC LEVELDB_PLATFORM_WINDOWS)
ELSE()
  target_include_directories(bshare
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/vendor/leveldb-1.12.0/include
    PRIVATE ${ZLIB_INCLUDE_DIRS}
    ${BITSHARES_DIR}/vendor/qtmacextras/include
  )
ENDIF()

# Here should be specified ALL dependencies of bshare library - Cmake will pass them automatically
# to the modules using bshare

#add_subdirectory( sancho )
#add_subdirectory( server )

#add_executable( wallet_test tests/wallet_test.cpp )
#target_link_libraries( wallet_test bshare )
#setup_library( bshare SOURCES ${sources} LIBRARY_TYPE STATIC )

#add_executable( unit_tests tests/unit_tests.cpp )
#target_link_libraries( unit_tests bshare ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY}  )

#add_executable( bitshares src/main.cpp )
#target_link_libraries( bitshares bshare )

#add_executable( bitchatc bitchat/main.cpp )
#target_link_libraries( bitchatc upnpc-static bshare fc ${BOOST_LIBRARIES} upnpc-static )

#add_executable( bitshared bitshared.cpp )
#target_link_libraries( bitshared bshare fc ${BOOST_LIBRARIES} )

#add_subdirectory( cli_client )
add_subdirectory( bts_wallet )
add_subdirectory( tests )
#add_subdirectory( founder_reg_server )
add_subdirectory( mail_server )

MESSAGE(STATUS "Finished Bitshares configuration...")

#include_directories( include )
#add_executable( test test.cpp  )
#target_link_libraries( test  bshare fc ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${READLINE_LIBRARIES} ${CMAKE_DL_LIBS})
