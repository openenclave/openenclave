# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## config.h:
##
## Modify and copy ./config.h to a temporary location within the binary 
## directory. The 'oembedtls-wrap' target below copies it into the MBEDTLS 
## source tree. Occurences of ${CMAKE_BUILD_TYPE} are expanded to either 
## "DEBUG" or "RELEASE"
##
##==============================================================================

string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h
    ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config.h)

##==============================================================================
##
## oembedtls-wrap:
##
## Builds MBEDTLS by performing the following steps.
##
## (1) Copy the ./mbedtls source tree to the following location in the binary 
##     directory.
##
##     ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/mbedtls-prefix/src/mbedtls
##
## (2) Copies the config.h (created above) into the MBEDTLS source tree.
##
## (3) Set the C compiler flags used to compile MBEDTLS.
##
## (4) Build MBEDTLS using the implicit default BUILD_COMMAND.
##
## (5) Create liboembedtls.a by combining the following archives.
##
##     libmbedtls.a
##     libmbedx509.a
##     libmbedcrypto.a
##
## MBEDTLS is compiled with these options:
##
##     -nostdinc
##     -I${ENCLAVELIBC_INCDIR}
##
## This forces MBEDTLS to look for the standard headers in the following
## location in the source tree:
##
##     openenclave/enclave/enclavelibc
##
## This directory contains header files with standard names like <stdlib.h>
## and <stdio.h>. These headers define their functions as inlines that invoke
## forms that have the 'oe_' prefix.
##
##==============================================================================

set(ENCLAVELIBC_INCDIR 
    "${PROJECT_SOURCE_DIR}/include/openenclave/internal/enclavelibc")

set(MBEDTLS_WRAP_CFLAGS "-Werror -nostdinc -I${ENCLAVELIBC_INCDIR} -fno-builtin -fPIC -fno-builtin-udivti3 -fno-stack-protector")

include(ExternalProject)

ExternalProject_Add(oembedtls-wrap

    # Copy the MBEDTLS source distribution to the build directory.
    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls <SOURCE_DIR>

    # Copy MBEDTLS config file into source tree under build directory.
    PATCH_COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config.h
        <SOURCE_DIR>/include/mbedtls/config.h

    # Define C compiler flags.
    CMAKE_ARGS
        -DCMAKE_C_FLAGS=${MBEDTLS_WRAP_CFLAGS}
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}

    # Intall MBEDTLS header directory and liboembedtls library.
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
        <SOURCE_DIR>/include/mbedtls ${OE_INCDIR}/openenclave/mbedtls
        COMMAND sh -c "rm -rf *.o"
        COMMAND sh -c "ar xs library/libmbedx509.a"
        COMMAND sh -c "ar xs library/libmbedtls.a"
        COMMAND sh -c "ar xs library/libmbedcrypto.a"
        COMMAND sh -c "ar qs library/liboembedtls.a *.o"
        COMMAND sh -c "rm -rf *.o"
        COMMAND ${CMAKE_COMMAND} -E copy
            <BINARY_DIR>/library/liboembedtls.a 
            ${OE_LIBDIR}/openenclave/enclave
)

##==============================================================================
##
## install:
##
## Install the MBEDTLS headers and binaries.
##
##==============================================================================

install(DIRECTORY 
    ${OE_INCDIR}/openenclave/mbedtls 
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES 
    ${OE_LIBDIR}/openenclave/enclave/liboembedtls.a
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

##==============================================================================
##
## oembedtls:
##
## Define the oembedtls interface so that other cmake files can find the
## MBEDTLS headers and library.
##
##==============================================================================

add_library(oembedtls INTERFACE)

add_dependencies(oembedtls oembedtls-wrap)

target_include_directories(oembedtls INTERFACE
    ${ENCLAVELIBC_INCDIR}
    ${OE_INCDIR}/openenclave)

target_link_libraries(oembedtls INTERFACE
    ${OE_LIBDIR}/openenclave/enclave/liboembedtls.a)

