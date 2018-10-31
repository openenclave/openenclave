# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enclave)
add_subdirectory(host)
add_executable(ocall-alloc_host host.cpp)
target_link_libraries(ocall-alloc_host oehostapp)
target_compile_options(ocall-alloc_host PRIVATE -Wconversion -Wpointer-arith)
