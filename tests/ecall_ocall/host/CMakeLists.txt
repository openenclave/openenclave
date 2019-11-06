# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../ecall_ocall.edl host gen)

add_executable(ecall_ocall_host host.cpp ${gen})

target_include_directories(ecall_ocall_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ecall_ocall_host oehostapp)
