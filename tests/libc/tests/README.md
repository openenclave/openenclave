libc tests
==========

The CMakeLists.txt file in this directory generates wrapper sources for every 
test in ../tests.supported. These sources are written to the build directory
and are used to build the test enclave (see ../enc).
