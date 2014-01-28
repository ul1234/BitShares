if (WIN32)
  set( PLATFORM_SPECIFIC_LIBS WS2_32 )
  ADD_DEFINITIONS(-DBOOST_TEST_DYN_LINK) 
else (WIN32)
  set( PLATFORM_SPECIFIC_LIBS )
endif(WIN32)

add_executable( bitshares_test bitshares_test.cpp )
target_link_libraries( bitshares_test ${rt_library} ${pthread_library} bshare fc leveldb ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} )

#add_executable( blockchain_tests blockchain_tests.cpp )
#target_link_libraries( blockchain_tests ${rt_library} ${pthread_library} bshare fc leveldb ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} )

#add_executable( pow_test pow_test.cpp )
#target_link_libraries( pow_test bshare fc ${BOOST_LIBRARIES} ${rt_library} ${pthread_library} )

add_executable( bitcoin_wallet_tests bitcoin_wallet_tests.cpp )
target_link_libraries( bitcoin_wallet_tests bshare fc ${BOOST_LIBRARIES} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} ${BDB_CXX_LIBRARIES} ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} )

add_executable( timekeeper timekeeper.cpp )
target_link_libraries( timekeeper bshare fc ${BOOST_LIBRARIES}  ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} )

add_executable( momentum_pow_test momentum_test.cpp )
target_link_libraries( momentum_pow_test bshare fc ${BOOST_LIBRARIES}  ${PLATFORM_SPECIFIC_LIBS} ${rt_library} ${pthread_library} )

#add_executable( evpow evpow.cpp )
#target_link_libraries( evpow fc ${BOOST_LIBRARIES}  ${PLATFORM_SPECIFIC_LIBS} )
