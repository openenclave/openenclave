# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../enclaveparam.edl enclave gen)

add_executable(enclaveparam_enc enc.c ${gen})

target_include_directories(enclaveparam_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclaveparam_enc oeenclave)
target_compile_options(enclaveparam_enc PRIVATE -Wconversion -Wpointer-arith)
