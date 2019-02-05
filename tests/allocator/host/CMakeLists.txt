# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../allocator.edl host gen)

add_executable(allocator_host host.c ${gen})

target_include_directories(allocator_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(allocator_host oehostapp)
