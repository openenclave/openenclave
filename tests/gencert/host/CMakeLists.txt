# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../oegencert.edl)

add_custom_command(
    OUTPUT oegencert_u.h oegencert_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --untrusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(oegencert_host host.c oegencert_u.c)

target_include_directories(oegencert_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oegencert_host oehostapp)
