# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(MBEDTLS_WRAP_CFLAGS "-nostdinc -I${OE_INCDIR}/openenclave/libc -fPIC -fno-builtin-udivti3 ${SPECTRE_MITIGATION_FLAGS}")

# Create a patched version of mbed TLS's `config.h` that the external
# project depends on.
string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE)
if ("${CMAKE_BUILD_TYPE}" STREQUAL "DEBUG")
  set(MBEDTLS_CERTS_C TRUE)
  set(MBEDTLS_DEBUG_C TRUE)
endif ()

configure_file(config.h config.h) # This copies from source to binary folders.

include(ExternalProject)
ExternalProject_Add(mbedtls-wrap
  DEPENDS oelibc_includes

  DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls <SOURCE_DIR>

  UPDATE_COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_CURRENT_BINARY_DIR}/config.h <SOURCE_DIR>/include/mbedtls/config.h

  CMAKE_ARGS
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_C_FLAGS=${MBEDTLS_WRAP_CFLAGS}
    -DENABLE_PROGRAMS=OFF
    -DENABLE_TESTING=OFF
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}

  # This is a no-op to override the default.
  INSTALL_COMMAND "")

ExternalProject_Get_property(mbedtls-wrap SOURCE_DIR)
ExternalProject_Get_property(mbedtls-wrap BINARY_DIR)

# NOTE: These imported libraries must be specified before `oelibc`
# when linking, hence their dependency on it.
add_library(mbedtls_imported IMPORTED STATIC)
set_target_properties(mbedtls_imported PROPERTIES
  IMPORTED_LOCATION ${BINARY_DIR}/library/libmbedtls.a)
target_link_libraries(mbedtls_imported INTERFACE oelibc)

add_library(mbedx509_imported IMPORTED STATIC)
set_target_properties(mbedx509_imported PROPERTIES
  IMPORTED_LOCATION ${BINARY_DIR}/library/libmbedx509.a)
target_link_libraries(mbedx509_imported INTERFACE oelibc)

add_library(mbedcrypto_imported IMPORTED STATIC)
set_target_properties(mbedcrypto_imported PROPERTIES
  IMPORTED_LOCATION ${BINARY_DIR}/library/libmbedcrypto.a)
target_link_libraries(mbedcrypto_imported INTERFACE oelibc)

# Convenience lib for use in target_link_libraries
add_library(mbedcrypto INTERFACE)

add_dependencies(mbedcrypto mbedtls-wrap)

target_include_directories(mbedcrypto INTERFACE
  $<BUILD_INTERFACE:${SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty>)

target_link_libraries(mbedcrypto INTERFACE
  $<BUILD_INTERFACE:mbedtls_imported>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_LIBDIR}/openenclave/enclave/libmbedtls.a>
  $<BUILD_INTERFACE:mbedx509_imported>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_LIBDIR}/openenclave/enclave/libmbedx509.a>
  $<BUILD_INTERFACE:mbedcrypto_imported>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_LIBDIR}/openenclave/enclave/libmbedcrypto.a>
  # NOTE: This dependency is repeated because during installation the
  # imported libraries are not part of the CMake dependency graph, so
  # this transitive dependency would be left out.
  oelibc)

install(TARGETS mbedcrypto EXPORT openenclave-targets)

install(DIRECTORY ${SOURCE_DIR}/include/mbedtls
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)

# NOTE: Because these libraries are `IMPORTED`, it is not possible
# with CMake to install them as targets, so instead they must be
# installed as files. This is what causes the above problem with the
# repeated dependency on `oelibc`.
install(FILES ${BINARY_DIR}/library/libmbedtls.a
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

install(FILES ${BINARY_DIR}/library/libmbedx509.a
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

install(FILES ${BINARY_DIR}/library/libmbedcrypto.a
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
