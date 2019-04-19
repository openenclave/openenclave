# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc1)
    add_subdirectory(enc2)
endif()

add_enclave_test(tests/sendmsg1 sendmsg_host sendmsg_enc1)
add_enclave_test(tests/sendmsg2 sendmsg_host sendmsg_enc2)
