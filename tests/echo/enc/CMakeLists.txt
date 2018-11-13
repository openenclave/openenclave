# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../echo.edl enclave gen)

add_executable(echo_enc enc.c ${gen})

target_include_directories(echo_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(echo_enc oeenclave)
target_compile_options(echo_enc PRIVATE -Wconversion -Wpointer-arith)
