# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(ocall_enc enc.cpp)
target_link_libraries(ocall_enc oeenclave)
target_compile_options(ocall_enc PRIVATE -Wconversion -Wpointer-arith)
