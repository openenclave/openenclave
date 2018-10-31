# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(ecall_enc enc.cpp)
target_link_libraries(ecall_enc oeenclave)
target_compile_options(ecall_enc PRIVATE -Wconversion -Wpointer-arith)
