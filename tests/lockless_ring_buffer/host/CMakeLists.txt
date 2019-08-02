# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#oeedl_file(../lockless_ring_buffer.edl host gen)

#add_executable(lockless_ring_buffer_host host.c ${gen})
add_executable(lockless_ring_buffer_host host.c)

target_include_directories(lockless_ring_buffer_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(lockless_ring_buffer_host oehostapp)
