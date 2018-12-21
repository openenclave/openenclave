# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


add_enclave(TARGET stdcxx_enc CXX SOURCES enc.cpp f.cpp)
add_enclave(TARGET global_init_exception_enc CXX SOURCES global_init_exception.cpp)

target_compile_options(stdcxx_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    -fno-builtin-fprintf
    -fno-builtin-printf
    )
