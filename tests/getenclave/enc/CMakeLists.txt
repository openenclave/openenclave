# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../getenclave.edl enclave gen)

add_enclave(TARGET getenclave_enc UUID 73c0418e-4d0f-49ef-905f-008f144eb297 SOURCES enc.c ${gen})

enclave_include_directories(getenclave_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(getenclave_enc oelibc)
