# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mbedssl.edl host gen --edl-search-dir ../../../device/edl)

add_executable(mbedssl_host host.c ${gen})

target_include_directories(mbedssl_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(mbedssl_host oehostapp)
