# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../oegencert.edl)

add_custom_command(
    OUTPUT oegencert_t.h oegencert_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --trusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET oegencert_enc
    UUID ef28dc39-208e-4b41-804b-408247d7faba
    SOURCES enc.c ${CMAKE_CURRENT_BINARY_DIR}/oegencert_t.c)

target_include_directories(oegencert_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oegencert_enc oeenclave oelibc oesyscall oehostfs oecore)
