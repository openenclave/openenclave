# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../create_in_thread.edl)

add_custom_command(
    OUTPUT create_in_thread_t.h create_in_thread_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET create_in_thread_enc UUID 688ab13f-5bc0-40af-8dc6-01d007fd2210 SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/create_in_thread_t.c)

enclave_include_directories(create_in_thread_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(create_in_thread_enc oelibc)
