# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../malloc.edl enclave gen)

add_enclave(TARGET malloc_enc SOURCES enc.c ${gen})

target_include_directories(malloc_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(malloc_enc oelibmalloc)
