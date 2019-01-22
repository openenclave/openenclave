# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../pingpong.edl enclave gen)
# TODO: Does this need CXX?
add_enclave(TARGET pingpong-shared_enc SOURCES enc.cpp ${gen})
target_include_directories(pingpong-shared_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong-shared_enc oelibc)
