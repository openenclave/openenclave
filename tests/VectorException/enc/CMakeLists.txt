# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../VectorException.edl enclave gen)

# TODO: Does this need CXX?
add_enclave(TARGET VectorException_enc UUID aa2379e1-ec26-4499-a396-18e9ce2228a4 SOURCES
    enc.c sigill_handling.c init.cpp ${gen})

target_include_directories(VectorException_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(VectorException_enc oelibc)
