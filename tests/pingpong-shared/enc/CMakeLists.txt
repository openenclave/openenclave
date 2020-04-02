# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../pingpong.edl)

add_custom_command(
    OUTPUT pingpong_t.h pingpong_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET pingpong-shared_enc UUID e229cc0f-3199-4ad3-91a7-47906fcbcc59 SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/pingpong_t.c)
enclave_include_directories(pingpong-shared_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(pingpong-shared_enc oelibc)
