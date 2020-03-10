# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../hexdump.edl enclave gen)

add_enclave(TARGET hexdump_enc UUID 126830b9-eb9f-412a-89a7-bcc8a517c12e SOURCES enc.c ${gen})

enclave_include_directories(hexdump_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(hexdump_enc oelibc)
