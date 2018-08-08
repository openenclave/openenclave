# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(CheckCXXCompilerFlag)

include(add_enclave_executable)
add_enclave_executable(print_enc sign.conf private.pem
    enc.cpp
    )

target_compile_options(print_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    )

check_cxx_compiler_flag(-Wno-error=unused-but-set-variable SUPPORTS_W_NO_UNUSED_BUT_SET_VAR_FLAG)
if (SUPPORTS_W_NO_UNUSED_BUT_SET_VAR_FLAG)
    target_compile_options(print_enc PRIVATE -Wno-error=unused-but-set-variable)
endif()

target_link_libraries(print_enc oeenclave)
