# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ecall_enc enc.cpp)
target_link_libraries(ecall_enc oeenclave)
