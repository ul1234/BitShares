add_executable( sancho main.cpp )
target_link_libraries( sancho upnpc-static bshare fc leveldb ${BOOST_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} upnpc-static ${rt_library} ${CMAKE_DL_LIBS})
add_executable( sanchoc client.cpp )
target_link_libraries( sanchoc  bshare fc leveldb ${BOOST_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS})
