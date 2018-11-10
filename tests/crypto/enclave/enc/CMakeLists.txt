# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)
oeedl_file(../crypto.edl enclave gen)

add_executable(cryptoenc
    enc.c
    ../../../../common/rand.S
    ../../read_file.c
    ../../asn1_tests.c
    ../../crl_tests.c
    ../../ec_tests.c
    ../../hash.c
    ../../hmac_tests.c
    ../../kdf_tests.c
    ../../random_tests.c
    ../../rdrand_test.c
    ../../rsa_tests.c
    ../../sha_tests.c
    ../../tests.c
     ${gen})


target_include_directories(cryptoenc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(cryptoenc oeenclave)
