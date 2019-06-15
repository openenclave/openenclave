# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../test_dup.edl host gen --edl-search-dir ../../../device/edl)

add_executable(dup_host host.c ${gen})

target_include_directories(dup_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(dup_host oehostapp)
