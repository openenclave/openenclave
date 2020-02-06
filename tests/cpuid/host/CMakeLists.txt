# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../cpuid.edl)

add_custom_command(
    OUTPUT cpuid_u.h cpuid_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --untrusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(cpuid_host host.c cpuid_u.c)

target_include_directories(cpuid_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(cpuid_host oehostapp)
