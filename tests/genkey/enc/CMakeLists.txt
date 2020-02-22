# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../genkey.edl)

add_custom_command(
    OUTPUT genkey_t.h genkey_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --trusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET genkey_enc
    UUID ef28dc39-208e-4b41-804b-408247d7faba
    SOURCES enc.c ${CMAKE_CURRENT_BINARY_DIR}/genkey_t.c)

target_include_directories(genkey_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(genkey_enc oeenclave oelibc oesyscall oehostfs oecore)
