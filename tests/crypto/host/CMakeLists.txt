# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# OS-specific source files
if (OE_SGX)
  if (UNIX)
    set(PLATFORM_SRC
      ../rdrand_test.c
      ../../../common/sgx/rand.S)
  elseif (WIN32)
    set(PLATFORM_SRC
      ../rdrand_test.c
      ../../../common/sgx/rand.asm)
  else ()
    message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
  endif ()
endif ()

if (UNIX)
  list(APPEND PLATFORM_SRC
    ../asn1_tests.c)
endif()

set(SRCS
  main.c
  ../crl_tests.c
  ../ec_tests.c
  ../hash.c
  ../hmac_tests.c
  ../kdf_tests.c
  ../random_tests.c
  ../read_file.c
  ../rsa_tests.c
  ../sha_tests.c
  ../tests.c
  ../utils.c)

add_executable(hostcrypto
  ${PLATFORM_SRC}
  ${SRCS})

add_dependencies(hostcrypto crypto_test_data)
target_link_libraries(hostcrypto oehost)
add_test(tests/crypto/host hostcrypto)
