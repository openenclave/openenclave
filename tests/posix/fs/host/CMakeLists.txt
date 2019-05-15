# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../fs.edl host gen
    --edl-search-dir ../../../../posix/devices/sgxfs)

add_executable(fs_host host.c ${gen})

target_include_directories(fs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (UNIX)
target_link_libraries(fs_host oesgxfshost oehostapp)
else ()
target_link_libraries(fs_host oehostapp)
endif()

