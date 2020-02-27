# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## host:
##
##==============================================================================

set (EDL_FILE oegencreds.edl)

add_custom_command(
    OUTPUT oegencreds_u.h oegencreds_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --untrusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(oegencreds main.c oegencreds_u.c)

target_include_directories(oegencreds PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oegencreds oehostapp)

##==============================================================================
##
## enc:
##
##==============================================================================

set (EDL_FILE oegencreds.edl)

add_custom_command(
    OUTPUT oegencreds_t.h oegencreds_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r
        --trusted ${EDL_FILE}
        --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET oegencreds_enclave
    UUID ef28dc39-208e-4b41-804b-408247d7faba
    SOURCES enclave.c oegencreds.c ${CMAKE_CURRENT_BINARY_DIR}/oegencreds_t.c)

target_include_directories(oegencreds_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oegencreds_enclave oeenclave oelibc oesyscall oecore)

##==============================================================================
##
## test:
##
##==============================================================================

add_test(NAME oegencreds COMMAND oegencreds)
