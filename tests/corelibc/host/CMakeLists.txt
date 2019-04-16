# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../corelibc.edl host gen --edl-search-dir ../../../device/edl)

add_executable(corelibc_host host.c ${gen})

target_include_directories(corelibc_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(corelibc_host oehostapp)
