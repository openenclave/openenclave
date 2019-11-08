# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../ecall.edl host gen)

add_executable(ecall_host host.cpp ${gen})

target_include_directories(ecall_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ecall_host oehostapp)
