# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(stdcenc sign.conf private.pem
    enc.cpp
    )

target_compile_options(stdcenc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    )

target_link_libraries(stdcenc oelibc oecore)
