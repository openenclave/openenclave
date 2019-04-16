# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mbedssl2.edl host gen --edl-search-dir ../../../device/edl)

add_executable(mbedssl2_host host.c ${gen})

target_include_directories(mbedssl2_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(mbedssl2_host oehostapp)
