Building
--------
Build is generally out-of-tree (in-tree is possible, though you would not
want that). To build, pick a dir to build under ("build/" below)
* mkdir build/
* cd build/
* cmake ..
* make

If things break, "make VERBOSE=1" gives all the gory details. You can build
from within a subtree of the build-tree, CMake is pretty good about chasing
dependencies. "make clean" works as well and is handy before a spot-rebuild
in verbose mode.

Testing
-------
After building, tests can be executed via ctest, see "man ctest" for details.
* From the build-tree, simply run "ctest"
* Simulation mode is only enabled upon explicit request via OE_SIMULATION=1
  in the environment.
* If things go wrong "ctest -V" gives details
* Executing ctest from a sub-dir executes the tests underneath.
* libcxx tests are omitted by default due to their huge cost on building
  (30mins+). Enable by including "-DENABLE_LIBCXX_TESTS=1" on the cmake line
  - cmake -DENABLE_LIBCXX_TESTS=ON ..
* If you are in a hurry and just need a quick confirmation, disable the libc
  tests with "-DENABLE_LIBC_TESTS=0".
* To run valgrind-tets, add "-D ExperimentalMemCheck" to the ctest call.
  Enclave tests all seem to fail today, though this suceeds:
  ctest -D ExperimentalMemCheck -R oeelf

Installation
------------
Specify the install-prefix (default /usr/local on Linux) to the cmake call:
* cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr/openenclave ..
* (then build via "make")
* make install

On Linux, there is also the DESTDIR mechanism, prepending the install prefix
with the given path:
* (cmake .. && make)
* make install DESTDIR=foo

Build configurations
--------------------
Different configurations (Debug, Release, RelWithDebInfo) are supported by
CMake pretty much out-of-the-box. Select when calling cmake, like so:
* cmake .. -DMAKE_BUILD_TYPE=relwithdebinfo

The default (none) results in no optimization, no non-debug flags, and no
debug symbols.

Documentation
-------------
HTML reference documentation is build by default and installed.
To update the refman *.md-files in the source-tree, issue "make refman-source"
from the build-tree.
