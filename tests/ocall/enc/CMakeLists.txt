# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../ocall.edl enclave gen)

add_enclave(TARGET ocall_enc UUID f39f25d8-266d-47ad-b9d3-77fb62100d14 SOURCES enc.cpp ${gen})

target_include_directories(ocall_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ocall_enc oelibcxx)
