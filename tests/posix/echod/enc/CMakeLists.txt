# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../echod.edl enclave gen)

add_executable(echod_enc enc.c ${gen})

# Add the directory containing echod_t.h to the include path.
target_include_directories(echod_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(echod_enc oelibc oeenclave)
