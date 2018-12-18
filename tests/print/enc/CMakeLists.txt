# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../print.edl enclave gen)

add_executable(print_enc enc.cpp ${gen})

target_compile_options(print_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    )

if (CMAKE_C_COMPILER_ID MATCHES GNU)
    target_compile_options(print_enc PRIVATE
        -Wno-error=unused-but-set-variable
        )
endif ()

target_include_directories(print_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(print_enc oeenclave)
