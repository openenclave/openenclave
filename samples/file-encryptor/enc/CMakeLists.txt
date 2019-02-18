# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../fileencryptor.edl enclave gen)

add_enclave(TARGET file-encryptor_enc CONFIG file-encryptor.conf CXX SOURCES ecalls.cpp encryptor.cpp keys.cpp ${gen})

target_include_directories(file-encryptor_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

