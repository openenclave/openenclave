# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(printenc sign.conf private.pem
    enc.cpp
    )

target_compile_options(printenc PRIVATE
    -Wno-error=unused-but-set-variable
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    )

target_link_libraries(printenc oeruntime)
