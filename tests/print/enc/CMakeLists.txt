# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_compile_flags_if_supported)

include(add_enclave_executable)
add_executable(print_enc enc.cpp)

target_compile_options(print_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    )

add_target_compile_flags_if_supported(print_enc PRIVATE CXX
    -Wno-error=unused-but-set-variable
    )

target_link_libraries(print_enc oeenclave)
