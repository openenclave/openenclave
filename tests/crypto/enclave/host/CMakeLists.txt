# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../crypto.edl host gen)

add_executable(cryptohost host.c ${gen})

target_include_directories(cryptohost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(cryptohost PRIVATE -Wconversion -Wpointer-arith)
target_link_libraries(cryptohost oehostapp)
