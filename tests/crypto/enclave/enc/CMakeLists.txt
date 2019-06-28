# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../crypto.edl enclave gen)

add_enclave(TARGET cryptoenc UUID f0be7db0-ce7c-4dc4-b8c8-b161f4216225
    SOURCES
    enc.c
    ../../../../common/sgx/rand.S
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
    ../../utils.c
    ${gen})

target_include_directories(cryptoenc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(cryptoenc oelibc)
