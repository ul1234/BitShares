
set( sources main.cpp )
add_executable( bitchat ${sources} )
target_link_libraries( bitchat bshare ${rt_library} ${CMAKE_DL_LIBS} )
