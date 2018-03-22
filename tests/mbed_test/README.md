
Currently the selftests won't perform mbedtls_timing_selftest() as it's underneath function are not supported by the enclave enviornment.
So this is disabled in the 3rdparty/mbedtls/mbedtls/include/mbedtls/config.h with the help of the macro "MBEDTLS_TIMING_C". Once the 
support is enbaled we will do support this test case under selftest().

