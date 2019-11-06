# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../argv.edl enclave gen)

add_enclave(TARGET argv_enc
    UUID c7d594f3-2d7a-4056-8d38-e0531926c676 SOURCES enc.c ${gen})

target_include_directories(argv_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(argv_enc oelibc)
