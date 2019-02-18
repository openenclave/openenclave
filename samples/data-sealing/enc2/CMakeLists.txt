# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../datasealing.edl enclave gen)

add_enclave(TARGET data-sealing_enc2 CONFIG data-sealing.conf CXX SOURCES ecalls.cpp  ${CMAKE_CURRENT_SOURCE_DIR}/../common/dispatcher.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../common/keys.cpp ${gen})

target_include_directories(data-sealing_enc2 PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)

