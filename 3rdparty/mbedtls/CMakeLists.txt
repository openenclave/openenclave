# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy mbedtls sources to replace config.h and build w/ own flags

set(ENCLAVELIBC_INCDIR 
    "${PROJECT_SOURCE_DIR}/include/openenclave/internal/enclavelibc")

set(MBEDTLS_WRAP_CFLAGS "-Werror -nostdinc -I${ENCLAVELIBC_INCDIR} -fno-builtin -fPIC -fno-builtin-udivti3 -fno-stack-protector")

string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "DEBUG")
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/config.h 
        ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config_final.h COPYONLY)
    file(APPEND 
        ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config_final.h 
        "\#define\ MBEDTLS_CERTS_C\n\n\#define\ MBEDTLS_DEBUG_C\n")
else()
    configure_file( 
        ${CMAKE_CURRENT_SOURCE_DIR}/config.h 
        ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config_final.h COPYONLY)
endif()

include(ExternalProject)

##==============================================================================
##
## ExternalProject_Add(mbedtls-wrap...)
##
##==============================================================================

ExternalProject_Add(mbedtls-wrap

    # Copy the MBEDTLS source distribution to the build directory.
    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls <SOURCE_DIR>

    # Copy MBEDTLS config file into source tree under build directory.
    PATCH_COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config_final.h 
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

install(DIRECTORY 
    ${OE_INCDIR}/openenclave/mbedtls 
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(FILES 
    ${OE_LIBDIR}/openenclave/enclave/liboembedtls.a
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

add_library(mbedcrypto INTERFACE)

add_dependencies(mbedcrypto mbedtls-wrap)

target_include_directories(mbedcrypto INTERFACE
    ${ENCLAVELIBC_INCDIR}
    ${OE_INCDIR}/openenclave)

target_link_libraries(mbedcrypto INTERFACE 
    ${OE_LIBDIR}/openenclave/enclave/liboembedtls.a)

