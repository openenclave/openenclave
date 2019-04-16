# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mbedssl3.edl host gen --edl-search-dir ../../../device/edl)

add_executable(mbedssl3_host host.c ${gen})

target_include_directories(mbedssl3_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(mbedssl3_host oehostapp)
