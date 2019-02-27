# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../VectorException.edl enclave gen)

# TODO: Does this need CXX?
add_enclave(TARGET VectorException_enc SOURCES
    enc.c sigill_handling.c init.cpp ${gen})

target_include_directories(VectorException_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(VectorException_enc oelibc)
