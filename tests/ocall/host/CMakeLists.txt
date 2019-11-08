# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../ocall.edl host gen)

add_executable(ocall_host host.cpp ${gen})

target_include_directories(ocall_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ocall_host oehostapp)
