# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../create_rapid.edl enclave gen)

# TODO: Does this need CXX?
add_enclave(TARGET create_rapid_enc SOURCES enc.cpp ${gen})

target_include_directories(create_rapid_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
