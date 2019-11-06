# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../ocall_create.edl host gen)

add_executable(ocall_create_host host.c ${gen})

target_include_directories(ocall_create_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ocall_create_host oehostapp)
