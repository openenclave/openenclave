# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(stdcxx_enc enc.cpp f.cpp)
add_executable(global_init_exception_enc global_init_exception.cpp)

target_compile_options(stdcxx_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    -fno-builtin-fprintf
    -fno-builtin-printf
    )

target_link_libraries(stdcxx_enc oelibcxx oeenclave)
target_link_libraries(global_init_exception_enc oelibcxx oeenclave)
