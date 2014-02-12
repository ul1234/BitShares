add_executable( cli_client main.cpp )
target_link_libraries( cli_client bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS} )
