# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../lockfile.edl enclave gen)

add_enclave(TARGET lockfile_enc
    UUID 71b0822f-42a3-4543-a97c-ca491f76b82c
    SOURCES enc.cpp ${gen})

target_include_directories(lockfile_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(lockfile_enc oelibc)
