# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(enclave_a ecalls.cpp)
target_link_libraries(enclave_a common)
target_include_directories(enclave_a PRIVATE ${CMAKE_BINARY_DIR}/enc1)
