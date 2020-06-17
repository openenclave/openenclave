# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# OS- and TEE-specific source files
if (OE_SGX)
  if (UNIX)
    set(PLATFORM_SRC ../../../common/sgx/rand.S)
  elseif (WIN32)
    set(PLATFORM_SRC ../../../common/sgx/rand.asm)
  else ()
    message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
  endif ()
endif ()

if (UNIX)
  list(APPEND PLATFORM_SRC ../asn1_tests.c)
endif ()

if (OE_SGX)
  list(APPEND PLATFORM_SRC ../cpu_entropy_test.c)
endif ()

add_executable(
  hostcrypto
  ${PLATFORM_SRC}
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

add_dependencies(hostcrypto crypto_test_data)
target_link_libraries(hostcrypto oehost)
add_test(tests/crypto/host hostcrypto)
