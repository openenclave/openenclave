# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# OS-specific source files
if (UNIX)
  set(PLATFORM_SRC
    ../asn1_tests.c
    ../crl_tests.c
    ../ec_tests.c
    ../read_file.c
    ../rsa_tests.c)
  if (OE_SGX)
    list(APPEND PLATFORM_SRC
      ../../../common/sgx/rand.S
      ../rdrand_test.c)
  endif ()
elseif (WIN32)
  set(PLATFORM_SRC
    ../../../common/sgx/rand.asm
    ../rdrand_test.c)
else ()
  message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
endif ()

add_executable(hostcrypto
  ${PLATFORM_SRC}
  main.c
  ../hash.c
  ../hmac_tests.c
  ../kdf_tests.c
  ../random_tests.c
  ../sha_tests.c
  ../tests.c
  ../utils.c)

add_dependencies(hostcrypto crypto_test_data)
target_link_libraries(hostcrypto oehost)
add_test(tests/crypto/host hostcrypto)
