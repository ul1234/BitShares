add_executable( mail_server main.cpp )
target_link_libraries( mail_server upnpc-static bshare fc leveldb ${BOOST_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} upnpc-static ${rt_library} ${CMAKE_DL_LIBS})

