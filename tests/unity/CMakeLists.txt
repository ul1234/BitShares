add_executable( unity_test main.cpp  )
target_link_libraries( unity_test  bshare fc leveldb ${BOOST_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} upnpc-static ${rt_library} ${READLINE_LIBRARIES} ${CMAKE_DL_LIBS})
