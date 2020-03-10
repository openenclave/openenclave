# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../ocall_create.edl enclave gen)

add_enclave(TARGET ocall_create_enc UUID 1b74ddb4-9c9c-47d7-b34c-56e58ab1df6f SOURCES enc.c ${gen})

enclave_include_directories(ocall_create_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(ocall_create_enc oelibc)
