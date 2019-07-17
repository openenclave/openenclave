# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../vector.edl enclave gen)

add_enclave(TARGET vector_enc
    UUID 71b0822f-42a3-4543-a97c-ca491f76b82c SOURCES enc.c ${gen})

target_include_directories(vector_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(vector_enc oelibc)
