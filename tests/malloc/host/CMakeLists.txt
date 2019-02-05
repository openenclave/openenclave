# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../malloc.edl host gen)

add_executable(malloc_host host.c ${gen})

target_include_directories(malloc_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(malloc_host oehostapp)
