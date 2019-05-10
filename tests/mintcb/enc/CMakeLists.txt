# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mintcb.edl enclave gen)

add_enclave(TARGET mintcb_enc SOURCES enc.c ${gen})

target_include_directories(mintcb_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(mintcb_enc oelibc -Wl,-e,oe_enter)
