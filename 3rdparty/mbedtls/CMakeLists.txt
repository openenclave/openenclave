# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy mbedtls sources to replace config.h and build w/ own flags

set(MBEDTLS_WRAP_CFLAGS "-nostdinc -I${OE_INCDIR}/openenclave/libc -fPIC -fno-builtin-udivti3")

include (ExternalProject)
ExternalProject_Add(mbedtls-wrap
    DEPENDS oelibc_includes

    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls <SOURCE_DIR>
    PATCH_COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/config.h <SOURCE_DIR>/include/mbedtls/config.h

    # Addl args for compiler
    CMAKE_ARGS
        -DCMAKE_C_FLAGS=${MBEDTLS_WRAP_CFLAGS}
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}

    # copy headers/libs
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
        <SOURCE_DIR>/include/mbedtls ${OE_INCDIR}/openenclave/oe-mbedtls/mbedtls
        COMMAND ${CMAKE_COMMAND} -E copy
        <BINARY_DIR>/library/libmbedx509.a ${OE_LIBDIR}/openenclave/enclave/
        <BINARY_DIR>/library/libmbedcrypto.a ${OE_LIBDIR}/openenclave/enclave/
    )
install (DIRECTORY ${OE_INCDIR}/openenclave/oe-mbedtls DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave)
install (FILES ${OE_LIBDIR}/openenclave/enclave/libmbedx509.a DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
install (FILES ${OE_LIBDIR}/openenclave/enclave/libmbedcrypto.a DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

# Convenience lib for use in target_link_libraries
add_library(mbedx509 INTERFACE)
add_library(mbedcrypto INTERFACE)
add_dependencies(mbedx509 mbedtls-wrap)
add_dependencies(mbedcrypto mbedtls-wrap)
target_include_directories(mbedcrypto INTERFACE ${OE_INCDIR}/openenclave/oe-mbedtls)
target_link_libraries(mbedcrypto INTERFACE
    ${OE_LIBDIR}/openenclave/enclave/libmbedx509.a
    ${OE_LIBDIR}/openenclave/enclave/libmbedcrypto.a)
# For the libc dependency, We would just want to use "oelibc". However, we need
# an actual lib-dependency between crypto an libc, which is not expressable
# with CMake. If using the target "oelibc", CMake reorders the libs, resulting
# in undefined LIBC symbols from crypto. Using the explicit lib-name preserves
# order.
target_link_libraries(mbedcrypto INTERFACE ${OE_LIBDIR}/openenclave/enclave/liboelibc.a)
