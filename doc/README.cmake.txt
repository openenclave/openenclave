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

Tests are executed via ctest, see "man ctest" for details.
* From the build-tree, simply run "ctest"
* If things go wrong "ctest -V" gives details
* Executing ctest from a sub-dir executes the tests underneath
* libcxx tests are omitted by default due to their huge cost on building
  (30mins+). Enable by including "-DENABLE_LIBCXX_TESTS=1" on the cmake line
  - cmake -DENABLE_LIBCXX_TESTS=ON ..
* if you are in a hurry, disable libc tests with "-DENABLE_LIBC_TESTS=0".

Installation:
Either by passing the install-prefix (default /usr/local on Linux) on the 
cmake call:
* cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr/openenclave ..
* (then build via "make")
* make install

On Linux, there is also the DESTDIR mechanism, prepending the install prefix
with the given path:
* (cmake .. && make)
* make install DESTDIR=foo

Different configurations (Debug, Release, RelWithDebInfo) are supported by
CMake pretty much out-of-the-box. Select when calling cmake, like so:
* cmake -DMAKE_BUILD_TYPE=relwithdebinfo ..

The default (none) results in no optimization, no non-debug flags, and no
debug symbols.
