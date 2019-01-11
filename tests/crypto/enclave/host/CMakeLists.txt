# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../crypto.edl host gen)

add_executable(cryptohost host.c ${gen})

target_include_directories(cryptohost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(cryptohost oehostapp)
