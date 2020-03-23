# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../VectorException.edl)

add_custom_command(
    OUTPUT VectorException_t.h VectorException_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# TODO: Does this need CXX?
add_enclave(TARGET VectorException_enc UUID aa2379e1-ec26-4499-a396-18e9ce2228a4 SOURCES
    enc.c sigill_handling.c init.cpp VectorException_t.c)

enclave_include_directories(VectorException_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(VectorException_enc oelibc)
