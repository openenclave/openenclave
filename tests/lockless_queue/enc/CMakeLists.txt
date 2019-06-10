# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../lockless_queue.edl enclave gen)

add_enclave(TARGET lockless_queue_enc SOURCES enc.c ${gen})

target_include_directories(lockless_queue_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(lockless_queue_enc oelibc)
