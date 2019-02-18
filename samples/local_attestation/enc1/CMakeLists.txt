# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../localattestation.edl enclave gen --output-dir ../common)

add_enclave(TARGET local_attestation_enc1 KEY ${CMAKE_CURRENT_BINARY_DIR}/private.pem CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/../common/enc.conf CXX SOURCES ${gen} ecalls.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../common/dispatcher.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../common/attestation.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../common/crypto.cpp)

target_include_directories(local_attestation_enc1 PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(local_attestation_enc1 oelibc)

