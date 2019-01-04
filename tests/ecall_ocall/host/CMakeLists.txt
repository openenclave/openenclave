# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ecall_ocall_host host.cpp)
target_link_libraries(ecall_ocall_host oehostapp)
