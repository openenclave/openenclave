# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../no_tdata.edl enclave gen)

# Build enclave that has no tdata
add_enclave(TARGET no_tdata_enc CXX SOURCES enc.cpp ${gen})

target_include_directories(no_tdata_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
