# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## host: tlssrv
##
##==============================================================================

set (EDL_FILE tlssrv.edl)

add_custom_command(
    OUTPUT tlssrv_u.h tlssrv_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --untrusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(tlssrv main.c tlssrv_u.c)

target_include_directories(tlssrv PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(tlssrv oehostapp)

##==============================================================================
##
## enclave: tlssrv_enclave
##
##==============================================================================

set (EDL_FILE tlssrv.edl)

add_custom_command(
    OUTPUT tlssrv_t.h tlssrv_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --trusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET tlssrv_enclave
    UUID 2c3ffd85-a31d-477b-9f0c-de22358b26cf
    SOURCES
        enclave.c
        tlssrv.c
        ${CMAKE_CURRENT_BINARY_DIR}/tlssrv_t.c)

target_include_directories(tlssrv_enclave PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(tlssrv_enclave
    oeenclave oelibc oesyscall oehostsock oehostresolver oecore)

##==============================================================================
##
## test:
##
##==============================================================================

add_test(NAME tlssrv COMMAND tlssrv)
