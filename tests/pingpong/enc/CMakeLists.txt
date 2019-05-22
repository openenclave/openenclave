# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../pingpong.edl enclave gen)
# TODO: Does this need CXX?
add_enclave(TARGET pingpong_enc UUID 0a6cbbd3-160a-4c86-9d9d-c9cf1956be16 SOURCES enc.cpp ${gen})
target_include_directories(pingpong_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong_enc oelibc)
