# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../file.edl enclave gen)
add_executable(file_enc
    enc.cpp
    ${gen}
    )

target_include_directories(file_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(file_enc oeenclave)
