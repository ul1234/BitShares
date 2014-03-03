if( UNIX ) 
  find_library(READLINE_LIBRARIES NAMES readline)
  find_path(READLINE_INCLUDE_DIR readline/readline.h)
  if(NOT READLINE_INCLUDE_DIR OR NOT READLINE_LIBRARIES)
    MESSAGE(FATAL_ERROR "Could not find lib readline.")
  endif()
endif()

add_executable( bts_wallet main.cpp chain_connection.cpp )
target_link_libraries( bts_wallet leveldb fc bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${READLINE_LIBRARIES} ${CMAKE_DL_LIBS})

add_executable( bts_server server.cpp chain_connection.cpp chain_server.cpp )
target_link_libraries( bts_server leveldb fc bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS} )

add_executable( get_bts_balance get_bts_balance.cpp )
target_link_libraries( get_bts_balance leveldb fc bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS} )

