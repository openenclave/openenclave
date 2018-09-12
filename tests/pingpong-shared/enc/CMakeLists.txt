# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeidl_file)
include(add_enclave_executable)

oeidl_file(../pingpong.idl enclave gen)
add_executable(pingpong-shared_enc enc.cpp ${gen})

target_include_directories(pingpong-shared_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong-shared_enc oeidl oelibc oeenclave)
