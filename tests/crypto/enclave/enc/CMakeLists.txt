# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)
oeedl_file(../crypto.edl enclave gen)

add_executable(cryptoenc
    enc.c
    ../../read_file.c
    ../../asn1_tests.c
    ../../crl_tests.c
    ../../ec_tests.c
    ../../hash.c
    ../../random_tests.c
    ../../rsa_tests.c
    ../../sha_tests.c
    ../../tests.c
     ${gen})


target_include_directories(cryptoenc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(cryptoenc PRIVATE -Wconversion -Wpointer-arith)
target_link_libraries(cryptoenc oeenclave)
