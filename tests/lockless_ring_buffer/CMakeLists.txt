# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


add_subdirectory(host)

#if (BUILD_ENCLAVES)
#   add_subdirectory(enc)
#endif()

#add_enclave_test(tests/lockless_ring_buffer lockless_ring_buffer_host lockless_ring_buffer_enc)
