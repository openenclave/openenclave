# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../helloworld.edl enclave gen)

add_enclave(TARGET helloworld_enc CONFIG helloworld.conf SOURCES enc.c ${gen})

target_include_directories(helloworld_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(helloworld_enc oelibc)
