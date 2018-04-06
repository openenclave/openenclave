# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/ecall_ocall host/ecall_ocall_host ./enc/ecall_ocall_enc.signed.so)
