# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../hexdump.edl host gen)

add_executable(hexdump_host host.c ${gen})

target_include_directories(hexdump_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(hexdump_host oehostapp)
