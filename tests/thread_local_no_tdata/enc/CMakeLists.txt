# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../no_tdata.edl enclave gen)

# Build enclave that has no tdata
add_enclave(TARGET no_tdata_enc UUID f60ab316-d838-4014-9909-09c0cf68fe65 CXX SOURCES enc.cpp ${gen})

enclave_include_directories(no_tdata_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
