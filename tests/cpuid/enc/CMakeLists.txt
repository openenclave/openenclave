# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../cpuid.edl)
add_custom_command(
    OUTPUT cpuid_t.h cpuid_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET cpuid_enc UUID 71b0822f-42a3-4543-a97c-ca491f76b82c SOURCES enc.c cpuid_t.c)

target_include_directories(cpuid_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(cpuid_enc oelibc)
