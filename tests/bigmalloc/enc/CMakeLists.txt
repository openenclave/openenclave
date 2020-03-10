# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.



oeedl_file(../bigmalloc.edl enclave gen)

# Unlike other tests, this test explicitly requires a signed enclave
# to test if a big enclave can be signed.
add_enclave(TARGET bigmalloc_enc UUID e4a54387-25fe-4b8f-b1ba-579eb525144f CONFIG sign.conf SOURCES enc.c ${gen})

enclave_include_directories(bigmalloc_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(bigmalloc_enc oelibc)
