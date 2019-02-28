# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../common/crypto_crls_cert_chains.edl enclave gen)

add_enclave(TARGET crypto-extra_enc CXX SOURCES enc.cpp ${gen})

target_include_directories(crypto-extra_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
