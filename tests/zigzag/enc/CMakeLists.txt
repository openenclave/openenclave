# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../zigzag.edl enclave gen)

add_enclave(TARGET zigzag_enc UUID 25253683-dbe2-45c3-9ba4-75ac00098317 SOURCES enc.c ${gen})

target_include_directories(zigzag_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(zigzag_enc oelibc)
