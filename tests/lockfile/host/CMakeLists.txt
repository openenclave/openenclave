# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../lockfile.edl host gen)

add_executable(lockfile_host host.cpp ${gen})

target_include_directories(lockfile_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(lockfile_host oehostapp)
