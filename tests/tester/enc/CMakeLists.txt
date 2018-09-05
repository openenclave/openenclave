# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeidl_file)
include(add_enclave_executable)

oeidl_file(../tester.idl enclave gen)
add_executable(tester_enc enc.cpp ${gen})

target_include_directories(tester_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(tester_enc oeidl oelibc oeenclave)
