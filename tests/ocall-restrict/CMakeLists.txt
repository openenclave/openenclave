# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/ocall-restrict host/ocall-restrict-host ./enc/ocall-restrict-enc.signed.so)
