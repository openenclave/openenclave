# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(stdcxx_enc enc.cpp f.cpp)

target_compile_options(stdcxx_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    -fno-builtin-fprintf
    -fno-builtin-printf
    -std=c++14
    -Wconversion
    -Wpointer-arith
    )

target_link_libraries(stdcxx_enc oelibcxx oeenclave)
