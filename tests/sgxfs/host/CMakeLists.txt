# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../test_sgxfs.edl host gen --edl-search-dir ../../../device/edl)

add_executable(sgxfs_host host.c ${gen})

target_include_directories(sgxfs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sgxfs_host oesgxfshost oehostapp)
