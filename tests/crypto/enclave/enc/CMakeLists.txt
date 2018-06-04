# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_enclave_executable(cryptoenc 
    sign.conf 
    private.pem 
    ec.c
    enc.c
    ../../ec_tests.c
    ../../hash.c
    ../../random_tests.c
    ../../rsa_tests.c
    ../../sha_tests.c)

target_link_libraries(cryptoenc oeenclave)
