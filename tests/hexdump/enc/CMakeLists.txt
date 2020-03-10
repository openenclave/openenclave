# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../hexdump.edl)

add_custom_command(
    OUTPUT hexdump_t.h hexdump_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET hexdump_enc UUID 126830b9-eb9f-412a-89a7-bcc8a517c12e SOURCES enc.c ${CMAKE_CURRENT_BINARY_DIR}/hexdump_t.c)

enclave_include_directories(hexdump_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(hexdump_enc oelibc)
