# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


#oeedl_file(${switchless_SOURCE_DIR}/switchless.edl enclave gen)

add_enclave(
    TARGET switchless_enc CXX SOURCES
    enc.cpp
    switchless_t.c
#    ${gen}
    )

target_include_directories(switchless_enc PRIVATE
    ${switchless_SOURCE_DIR}/shared
#    ${CMAKE_CURRENT_BINARY_DIR}
#    ${CMAKE_CURRENT_SOURCE_DIR}
    )

target_link_libraries(switchless_enc oeenclave)
