# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# TODO: Does this need CXX?

oeedl_file(../ecall.edl enclave gen)

add_enclave(TARGET ecall_enc UUID 985c1ef2-d780-4092-af68-0258d0cc691d SOURCES enc.cpp ${gen})

target_include_directories(ecall_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ecall_enc oelibc)
