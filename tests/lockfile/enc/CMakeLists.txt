# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../lockfile.edl enclave gen)

add_enclave(TARGET lockfile_enc
    UUID b56abe89-1575-461d-96da-ef1b814a019b
    SOURCES enc.cpp ${gen})

target_include_directories(lockfile_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(lockfile_enc oelibc)
