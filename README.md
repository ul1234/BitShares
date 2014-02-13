bitshares - Polymorphic Digital Asset Library
=========

BitShares is a new blockchain that pays dividends and enables users
to short and trade any arbitrary asset type.


Project Status
------------
This code is only fit for developers and the api, design is evolving
rapidly.  If you would like to be involved please contact me via
github or bytemaster on bitcointalk.org   

Dependencies
-------------------
	g++ 4.6, VC2012, clang++ 3.2 (apple)
	boost 1.54
	OpenSSL
	cmake 2.8.12
  libreadline-dev

OS X Build Instructions
-----------------------
Download the latest boost and build it with clang++ with support for static libraries like so
  
  sudo ./b2 toolset=clang cxxflags="-stdlib=libc++" linkflags="-stdlib=libc++" link=static install


Build
--------------------

	git clone https://github.com/InvictusInnovations/BitShares.git
	cd BitShares
	git clone https://github.com/InvictusInnovations/fc.git
	cmake .
	make 

Coding Standards
----------------
all lower case names with underscores with the exception of macros.
private implmentation classes in the detail namespace.
Make it look like the rest of the code.



