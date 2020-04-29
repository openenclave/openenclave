# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE "../fs.edl")

if(UNIX)
    set(HOSTSRC "host_linux.c")
else()
    set(HOSTSRC "host_win32.c")
endif()

add_custom_command(
    OUTPUT fs_u.h fs_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --untrusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(fs_host ${HOSTSRC} fs_u.c)

target_include_directories(fs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (TEST_SGXFS)
    target_compile_definitions(fs_host PRIVATE TEST_SGXFS=1)
    set(OESGXFSHOST oesgxfshost)
else()
    set(OESGXFSHOST "")
endif()

target_link_libraries(fs_host ${OESGXFSHOST} oehostapp)

if(UNIX)
    set_source_files_properties(${HOSTSRC}
        PROPERTIES
        COMPILE_FLAGS " -Wno-unused-parameter")
endif()
