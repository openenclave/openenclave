# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ecall_ocall_host
    ../crc32.cpp
    host.cpp
    )
target_compile_options(ecall_ocall_host PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    )
target_link_libraries(ecall_ocall_host oehostapp)
