add_executable( mail_server main.cpp )
target_link_libraries( mail_server bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS})

