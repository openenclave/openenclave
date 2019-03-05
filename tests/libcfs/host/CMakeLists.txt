# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../libcfs.edl host gen)

add_executable(libcfs_host host.c ${gen})

target_include_directories(libcfs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(libcfs_host oesgxfshost oehostapp)
