# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../array.edl enclave gen)

add_enclave(TARGET array_enc SOURCES enc.c ${gen})

target_include_directories(array_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(array_enc oelibc)
