add_executable( sancho main.cpp )
target_link_libraries( sancho bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS})
add_executable( sanchoc client.cpp )
target_link_libraries( sanchoc  bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS})
