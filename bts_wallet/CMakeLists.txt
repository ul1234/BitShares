
add_executable( bts_wallet main.cpp chain_connection.cpp )
target_link_libraries( bts_wallet leveldb fc bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS})

add_executable( bts_server server.cpp chain_connection.cpp chain_server.cpp )
target_link_libraries( bts_server leveldb fc bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS} )

add_executable( get_bts_balance get_bts_balance.cpp )
target_link_libraries( get_bts_balance leveldb fc bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS} )

