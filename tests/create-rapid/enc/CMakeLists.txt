# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../create_rapid.edl enclave gen)

add_executable(create_rapid_enc enc.cpp ${gen})

target_include_directories(create_rapid_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(create_rapid_enc oeenclave)
target_compile_options(create_rapid_enc PRIVATE -Wconversion -Wpointer-arith)
