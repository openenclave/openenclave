# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../create_rapid.edl)

add_custom_command(
    OUTPUT create_rapid_t.h create_rapid_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET create_rapid_enc UUID 688ab13f-5bc0-40af-8dc6-01d007fd2210 SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/create_rapid_t.c)

enclave_include_directories(create_rapid_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(create_rapid_enc oelibc)
