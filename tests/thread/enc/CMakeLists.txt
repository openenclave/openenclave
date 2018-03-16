# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(threadenc sign.conf private.pem
    enc.cpp
    cond_tests.cpp
    rwlock_tests.cpp
    )

target_compile_options(threadenc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    )

target_link_libraries(threadenc oelibc oelibcxx)
