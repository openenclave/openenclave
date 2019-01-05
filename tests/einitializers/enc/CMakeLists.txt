# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../test.edl enclave gen)

add_enclave(TARGET einitializers_enc SOURCES enc.c ${gen})

target_include_directories(einitializers_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(einitializers_enc enclib1 enclib2)
