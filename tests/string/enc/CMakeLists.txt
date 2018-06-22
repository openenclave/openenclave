# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_enclave_executable(string_enc sign.conf private.pem enc.c)

target_link_libraries(string_enc oecore)
