# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../crypto.edl)

add_custom_command(
    OUTPUT crypto_t.h crypto_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(SRCS
    enc.c
    ../../read_file.c
    ../../asn1_tests.c
    ../../crl_tests.c
    ../../ec_tests.c
    ../../hash.c
    ../../hmac_tests.c
    ../../kdf_tests.c
    ../../random_tests.c
    ../../rsa_tests.c
    ../../sha_tests.c
    ../../tests.c
    ../../utils.c)

if (OE_SGX)
    list(APPEND SRCS
        ../../../../common/sgx/rand.S
        ../../cpu_entropy_test.c)
endif ()

add_enclave(TARGET crypto_enc UUID f0be7db0-ce7c-4dc4-b8c8-b161f4216225
    SOURCES ${SRCS} crypto_t.c)

enclave_include_directories(crypto_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(crypto_enc oelibc)
