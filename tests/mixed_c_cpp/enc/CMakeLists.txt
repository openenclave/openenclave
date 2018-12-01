# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../mixed.edl enclave gen)
add_executable(mixed_c_cpp_enc
    enc.cpp
    foo.c
    ${gen}
    )

target_include_directories(mixed_c_cpp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(mixed_c_cpp_enc oelibcxx oeenclave)
