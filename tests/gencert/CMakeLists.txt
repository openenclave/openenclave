# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## host:
##
##==============================================================================

set (EDL_FILE oegencert.edl)

add_custom_command(
    OUTPUT oegencert_u.h oegencert_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --untrusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(oegencert host.c oegencert_u.c)

target_include_directories(oegencert PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oegencert oehostapp)

##==============================================================================
##
## enc:
##
##==============================================================================

set (EDL_FILE oegencert.edl)

add_custom_command(
    OUTPUT oegencert_t.h oegencert_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --trusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET oegencert_enclave
    UUID ef28dc39-208e-4b41-804b-408247d7faba
    SOURCES enc.c oegencert.c ${CMAKE_CURRENT_BINARY_DIR}/oegencert_t.c)

target_include_directories(oegencert_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oegencert_enclave
    oeenclave oelibc oesyscall oehostfs oecore)

##==============================================================================
##
## test:
##
##==============================================================================

add_test(NAME oegencert COMMAND oegencert)
