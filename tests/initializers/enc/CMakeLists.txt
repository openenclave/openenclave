# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../initializers.edl enclave gen)

add_executable(initializers_enc enc.c ${gen})

target_include_directories(initializers_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(initializers_enc oeenclave)
target_compile_options(initializers_enc PRIVATE -Wconversion -Wpointer-arith)
