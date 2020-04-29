# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../enclaveparam.edl)

add_custom_command(
    OUTPUT enclaveparam_t.h enclaveparam_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET enclaveparam_enc UUID c0c6e0fe-7c40-485a-beaf-4145293cd69a SOURCES enc.c ${CMAKE_CURRENT_BINARY_DIR}/enclaveparam_t.c)

enclave_include_directories(enclaveparam_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(enclaveparam_enc oelibc)
