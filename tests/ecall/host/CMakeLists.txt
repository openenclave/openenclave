# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ecall_host host.cpp)
target_link_libraries(ecall_host oehostapp)
target_compile_options(ecall_host PRIVATE -Wconversion -Wpointer-arith)
