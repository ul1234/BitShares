if (MSVC)
    FIND_PATH(BDB_CXX_INCLUDE_DIR NAMES db.h db_cxx.h
          PATHS $ENV{DBROOTDIR}
          PATH_SUFFIXES include)
	#set(_tmp_prefixes ${CMAKE_FIND_LIBRARY_PREFIXES})
	#set(CMAKE_FIND_LIBRARY_PREFIXES "libdb" ${CMAKE_FIND_LIBRARY_PREFIXES})
    FIND_LIBRARY(BDB_CXX_LIBRARIES libdb${DB_VERSION}
                 PATHS ${DB_ROOT_DIR} $ENV{DBROOTDIR} ${BDB_CXX_INCLUDE_DIR}
                       /usr/local/lib
                 PATH_SUFFIXES lib)
	#set(CMAKE_FIND_LIBRARY_PREFIXES ${_tmp_prefixes})
    
else (MSVC)
    FIND_PATH(BDB_CXX_INCLUDE_DIR db.h
    /usr/include/libdb5
    /usr/include/db5
    /usr/include/libdb4
    /usr/include/db4
    /usr/local/include/libdb5
    /usr/local/include/db5
    /usr/local/include/libdb4
    /usr/local/include/db4
    )

    FIND_LIBRARY(BDB_CXX_LIBRARIES NAMES db_cxx
    /usr/local/lib
    )
endif (MSVC)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Berkeley "Could not find Berkeley DB >= 4.1" BDB_CXX_INCLUDE_DIR BDB_CXX_LIBRARIES)