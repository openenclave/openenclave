# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include (ExternalProject)

if (UNIX)
# Copy mbedtls sources to replace config.h and build w/ own flags
set(MBEDTLS_WRAP_CFLAGS "-nostdinc -I${OE_INCDIR}/openenclave/libc -fPIC -fno-builtin-udivti3 ${SPECTRE_MITIGATION_FLAGS}")

string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "DEBUG")
	configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/config.h ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config_final.h COPYONLY)
	file(APPEND ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config_final.h "\#define\ MBEDTLS_CERTS_C\n\n\#define\ MBEDTLS_DEBUG_C\n")
else()
	configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/config.h ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config_final.h COPYONLY)
endif()

ExternalProject_Add(mbedtls-wrap
    DEPENDS oelibc_includes

    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls <SOURCE_DIR>
    PATCH_COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/config_final.h <SOURCE_DIR>/include/mbedtls/config.h
    # Addl args for compiler
    CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_C_FLAGS=${MBEDTLS_WRAP_CFLAGS}
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}

    # copy headers/libs
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
        <SOURCE_DIR>/include/mbedtls ${OE_INCDIR}/openenclave/mbedtls
        COMMAND ${CMAKE_COMMAND} -E copy
        <BINARY_DIR>/library/libmbedx509.a ${OE_LIBDIR}/openenclave/enclave/
        <BINARY_DIR>/library/libmbedtls.a ${OE_LIBDIR}/openenclave/enclave/
        <BINARY_DIR>/library/libmbedcrypto.a ${OE_LIBDIR}/openenclave/enclave/
    )
install (DIRECTORY ${OE_INCDIR}/openenclave/mbedtls DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
install (FILES ${OE_LIBDIR}/openenclave/enclave/libmbedtls.a DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
install (FILES ${OE_LIBDIR}/openenclave/enclave/libmbedx509.a DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
install (FILES ${OE_LIBDIR}/openenclave/enclave/libmbedcrypto.a DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

# Convenience lib for use in target_link_libraries
add_library(mbedcrypto INTERFACE)
add_dependencies(mbedcrypto mbedtls-wrap)
target_include_directories(mbedcrypto INTERFACE ${OE_INCDIR}/openenclave/)
target_link_libraries(mbedcrypto INTERFACE 
    ${OE_LIBDIR}/openenclave/enclave/libmbedtls.a
    ${OE_LIBDIR}/openenclave/enclave/libmbedx509.a
    ${OE_LIBDIR}/openenclave/enclave/libmbedcrypto.a
)
# For the libc dependency, We would just want to use "oelibc". However, we need
# an actual lib-dependency between crypto an libc, which is not expressable
# with CMake. If using the target "oelibc", CMake reorders the libs, resulting
# in undefined LIBC symbols from crypto. Using the explicit lib-name preserves
# order.
target_link_libraries(mbedcrypto INTERFACE
	${OE_LIBDIR}/openenclave/enclave/liboelibc.a
	${OE_LIBDIR}/openenclave/enclave/liboecore.a)

else()
# On Windows, we compile the mbedcrypto library so we can use it for the bignum functions.

if (CMAKE_GENERATOR MATCHES "Visual Studio")
    set(MBEDTLS_LIBRARY_NAME "${CMAKE_BUILD_TYPE}/mbedcrypto.lib")
else()
    set(MBEDTLS_LIBRARY_NAME "mbedcrypto.lib")
endif()

ExternalProject_Add(mbedtls-wrap-host
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls

    CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}

    INSTALL_COMMAND
        COMMAND ${CMAKE_COMMAND} -E make_directory ${OE_LIBDIR}/openenclave/host/
        COMMAND ${CMAKE_COMMAND} -E copy
        <BINARY_DIR>/library/${MBEDTLS_LIBRARY_NAME} ${OE_LIBDIR}/openenclave/host/
)
install (FILES ${OE_LIBDIR}/openenclave/host/${MBEDTLS_LIBRARY_NAME} DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

ExternalProject_Get_Property(mbedtls-wrap-host BINARY_DIR)
add_library(mbedcryptohost INTERFACE)
add_dependencies(mbedcryptohost mbedtls-wrap-host)
target_link_libraries(mbedcryptohost INTERFACE ${BINARY_DIR}/library/${MBEDTLS_LIBRARY_NAME})
install(TARGETS mbedcryptohost EXPORT openenclave-targets)

endif()
