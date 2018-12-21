# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)


oeedl_file(../mixed.edl enclave gen)
add_enclave(TARGET mixed_c_cpp_enc CXX SOURCES enc.cpp foo.c ${gen})
target_include_directories(mixed_c_cpp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
