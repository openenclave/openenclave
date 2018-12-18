# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../bigmalloc.edl enclave gen)

# Unlike other tests, this test explicitly requires a signed enclave
# to test if a big enclave can be signed.
add_enclave_executable(bigmalloc_enc sign.conf
    enc.c
    ${gen}
    )

target_include_directories(bigmalloc_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(bigmalloc_enc oeenclave)
