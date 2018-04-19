# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_cxx_enclave_executable(stdcxxenc sign.conf private.pem
    enc.cpp
    f.cpp
    )

target_compile_options(stdcxxenc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    -fno-builtin-fprintf
    -fno-builtin-printf
    )

target_link_libraries(stdcxxenc oelibcxx)
