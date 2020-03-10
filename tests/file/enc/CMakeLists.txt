# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../file.edl enclave gen)
# TODO: Does this need CXX?
add_enclave(TARGET file_enc UUID f7ee9123-07ec-4d46-81ac-47a109b1d406 SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/file_t.c)
enclave_include_directories(file_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(file_enc oelibc)
