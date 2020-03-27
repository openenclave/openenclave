# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../getenclave.edl)

add_custom_command(
    OUTPUT getenclave_t.h getenclave_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET getenclaveext_enc UUID 671f136d-d0df-43b9-8560-15497efaff21 SOURCES enc.c ${CMAKE_CURRENT_BINARY_DIR}/getenclave_t.c)

enclave_compile_definitions(getenclaveext_enc PRIVATE DEBUG)
enclave_include_directories(getenclaveext_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(getenclaveext_enc oelibc)

add_enclave(TARGET getenclaveext_enc_nondebug UUID 73c0418e-4d0f-49ef-905f-008f144eb297 SOURCES enc.c ${CMAKE_CURRENT_BINARY_DIR}/getenclave_t.c)

enclave_include_directories(getenclaveext_enc_nondebug PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(getenclaveext_enc_nondebug oelibc)
