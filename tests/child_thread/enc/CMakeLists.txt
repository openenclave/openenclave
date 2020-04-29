# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../child_thread.edl)

add_custom_command(
    OUTPUT child_thread_t.h child_thread_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET child_thread_enc CXX UUID 99313d27-e655-4505-903b-dda158c4ee3e SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/child_thread_t.c)

enclave_include_directories(child_thread_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(child_thread_enc oelibc)
