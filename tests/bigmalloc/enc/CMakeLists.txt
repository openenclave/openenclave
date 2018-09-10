# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

# Unlike other tests, this test explicitly requires a signed enclave
# to test if a big enclave can be signed.
add_enclave_executable(bigmalloc_enc sign.conf private.pem
    enc.c
    )

target_link_libraries(bigmalloc_enc oeenclave)
