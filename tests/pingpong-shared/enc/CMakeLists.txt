# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../pingpong.edl enclave gen)
# TODO: Does this need CXX?
add_enclave(TARGET pingpong-shared_enc UUID e229cc0f-3199-4ad3-91a7-47906fcbcc59 SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/pingpong_t.c)
enclave_include_directories(pingpong-shared_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(pingpong-shared_enc oelibc)
