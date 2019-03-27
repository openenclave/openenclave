# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(enclave_b ecalls.cpp)
target_link_libraries(enclave_b common)
