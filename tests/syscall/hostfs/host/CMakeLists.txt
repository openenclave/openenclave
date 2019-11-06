# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../test_hostfs.edl host gen --edl-search-dir ../../../device/edl)

add_executable(hostfs_host host.c ${gen})

target_include_directories(hostfs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(hostfs_host oehostapp)
