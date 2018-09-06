# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_executable(cryptoenc
    enc.c
    ../../asn1_tests.c
    ../../crl_tests.c
    ../../ec_tests.c
    ../../hash.c
    ../../random_tests.c
    ../../rsa_tests.c
    ../../sha_tests.c
    ../../tests.c)

target_link_libraries(cryptoenc oeenclave)
