# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.



oeedl_file(../mixed.edl enclave gen)
add_enclave(TARGET mixed_c_cpp_enc UUID 952c55c8-59f3-47a0-814c-ae3276a9808f CXX SOURCES enc.cpp foo.c ${gen})
target_include_directories(mixed_c_cpp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
