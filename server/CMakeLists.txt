add_executable( bitshares_server messages.cpp server.cpp )
target_link_libraries( bitshares_server bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS})

add_executable( bitshares_client messages.cpp client.cpp )
target_link_libraries( bitshares_client bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS})
