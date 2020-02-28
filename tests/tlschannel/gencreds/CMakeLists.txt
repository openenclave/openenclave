# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## host:
##
##==============================================================================

set (EDL_FILE gencreds.edl)

add_custom_command(
    OUTPUT gencreds_u.h gencreds_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --untrusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(oegencreds main.c gencreds_u.c)

target_include_directories(oegencreds PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oegencreds oehostapp)

##==============================================================================
##
## enclave:
##
##==============================================================================

set (EDL_FILE gencreds.edl)

add_custom_command(
    OUTPUT gencreds_t.h gencreds_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --trusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET gencreds_enclave
    UUID ef28dc39-208e-4b41-804b-408247d7faba
    SOURCES
        enclave.c
        ../common/gencreds.c
        ${CMAKE_CURRENT_BINARY_DIR}/gencreds_t.c)

target_include_directories(gencreds_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(gencreds_enclave oeenclave oelibc oesyscall oecore)

##==============================================================================
##
## test:
##
##==============================================================================

set(CERT "${CMAKE_CURRENT_BINARY_DIR}/cert.der")
set(PRIVATE_KEY "${CMAKE_CURRENT_BINARY_DIR}/private_key.pem")

add_test(NAME oegencreds COMMAND oegencreds ${CERT} ${PRIVATE_KEY})
