# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../socketpair_test.edl 
    enclave socketpair_test_t
    --edl-search-dir ../../../include
)

add_enclave(TARGET socketpair_enc SOURCES enc.c ${socketpair_test_t})

enclave_include_directories(socketpair_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(socketpair_enc oelibc oehostsock)
