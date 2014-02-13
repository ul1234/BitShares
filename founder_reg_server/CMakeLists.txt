
add_executable( name_reg_server main.cpp )
target_link_libraries( name_reg_server bshare ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${CMAKE_DL_LIBS})
