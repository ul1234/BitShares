if (WIN32)
  set( PLATFORM_SPECIFIC_LIBS WS2_32 )
  ADD_DEFINITIONS(-DBOOST_TEST_DYN_LINK) 
else (WIN32)
  set( PLATFORM_SPECIFIC_LIBS )

#  add_subdirectory( unity )
endif(WIN32)


#add_executable( market_db_test market_db_test.cpp )
#target_link_libraries( market_db_test ${rt_library} ${pthread_library} bshare fc leveldb ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} ${CMAKE_DL_LIBS} )
   
#add_executable( bitshares_test bitshares_test.cpp )
#target_link_libraries( bitshares_test ${rt_library} ${pthread_library} bshare fc leveldb ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} ${CMAKE_DL_LIBS} )

#add_executable( blockchain_tests blockchain_tests.cpp )
#target_link_libraries( blockchain_tests ${rt_library} ${pthread_library} bshare fc leveldb ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} )

#add_executable( pow_test pow_test.cpp )
#target_link_libraries( pow_test bshare fc ${BOOST_LIBRARIES} ${rt_library} ${pthread_library} )

#add_executable( bitcoin_wallet_tests bitcoin_wallet_tests.cpp )
#target_link_libraries( bitcoin_wallet_tests bshare fc ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${BDB_CXX_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} ${CMAKE_DL_LIBS} )

#add_executable( electrum_wallet_tests electrum_wallet_tests.cpp )
#target_link_libraries( electrum_wallet_tests bshare fc ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} ${CMAKE_DL_LIBS} )

#add_executable( multibit_wallet_tests multibit_wallet_tests.cpp )
#target_link_libraries( multibit_wallet_tests bshare fc ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} ${CMAKE_DL_LIBS} )

#add_executable( timekeeper timekeeper.cpp )
#target_link_libraries( timekeeper bshare fc ${BOOST_LIBRARIES}  ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} ${CMAKE_DL_LIBS} )

add_executable( momentum_pow_test momentum_test.cpp )
target_link_libraries( momentum_pow_test bshare fc ${BOOST_LIBRARIES}  ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} ${CMAKE_DL_LIBS} )

#add_executable( evpow evpow.cpp )
#target_link_libraries( evpow fc ${BOOST_LIBRARIES}  ${PLATFORM_SPECIFIC_LIBS} )

#IF(KH_STATIC_QT EQUAL 1)
#   # Use dedicated prefix to find static versions of libraries 
#   SET(ICU_LIBS_PREFIX "s")
#ENDIF()
#find_package( ICU )
#MESSAGE("Found ICU version ${ICU_VERSION}")
#if (NOT ${ICU_VERSION} EQUAL "52.1")
#  # 53.1 might be ok too, need to test it
#  MESSAGE(FATAL_ERROR "Error, BitShares require ICU version 52.1")
#endif()

#add_executable( khid_test khid_test.cpp )
#target_link_libraries( khid_test bshare fc ${BOOST_LIBRARIES} ${ICU_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} ${CMAKE_DL_LIBS} )
#target_include_directories(khid_test PRIVATE ${ICU_INCLUDE_DIRS})