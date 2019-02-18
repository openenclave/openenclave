# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../remoteattestation.edl enclave gen --output-dir ../common)

add_enclave(TARGET remote_attestation_enc2 KEY ${CMAKE_CURRENT_BINARY_DIR}/private.pem CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/../common/enc.conf CXX SOURCES ecalls.cpp  ${CMAKE_CURRENT_SOURCE_DIR}/../common/dispatcher.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../common/attestation.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../common/crypto.cpp ${gen})

target_include_directories(remote_attestation_enc2 PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(remote_attestation_enc2 oelibc)

