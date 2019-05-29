# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../lockless_queue.edl host gen)

add_executable(lockless_queue_host host.c ${gen})

target_include_directories(lockless_queue_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(lockless_queue_host oehostapp)
