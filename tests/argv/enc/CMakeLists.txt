# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../argv.edl enclave gen)

add_enclave(TARGET argv_enc
    UUID 71b0822f-42a3-4543-a97c-ca491f76b82c SOURCES enc.c ${gen})

target_include_directories(argv_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(argv_enc oelibc)
