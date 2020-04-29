# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../stdc.edl)

add_custom_command(
    OUTPUT stdc_t.h stdc_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET stdc_enc UUID 9a30506a-87f6-4214-a007-f15b11c98f8b SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/stdc_t.c)

enclave_compile_options(stdc_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    )

enclave_include_directories(stdc_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

enclave_link_libraries(stdc_enc oelibc)
