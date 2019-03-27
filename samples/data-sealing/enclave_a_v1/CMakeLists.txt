# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(enclave_a_v1 ecalls.cpp)
target_link_libraries(enclave_a_v1 common)
