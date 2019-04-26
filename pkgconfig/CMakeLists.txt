# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## Prefix where Open Enclave is installed.
##
##==============================================================================

set(PREFIX "${CMAKE_INSTALL_PREFIX}")

##==============================================================================
##
## Enclave compiler flags:
##
##==============================================================================

set(ENCLAVE_CINCLUDES
    "-I\${includedir}/openenclave/3rdparty/libc -I\${includedir}/openenclave/3rdparty -I\${includedir}")

set(ENCLAVE_CXXINCLUDES
    "-I\${includedir}/openenclave/3rdparty/libcxx ${ENCLAVE_CINCLUDES}")

set(ENCLAVE_CFLAGS_LIST
  -nostdinc
  -m64
  -fPIE
  -ftls-model=local-exec
  -fvisibility=hidden
  -fno-stack-protector)

set(ENCLAVE_CFLAGS_CLANG_LIST ${ENCLAVE_CFLAGS_LIST} ${SPECTRE_MITIGATION_FLAGS})
list(JOIN ENCLAVE_CFLAGS_CLANG_LIST " " ENCLAVE_CFLAGS_CLANG)

list(JOIN ENCLAVE_CFLAGS_LIST " " ENCLAVE_CFLAGS_GCC)

##==============================================================================
##
## Enclave linker flags:
##
##==============================================================================

set(ENCLAVE_CLIBS_1
  -nostdlib
  -nodefaultlibs
  -nostartfiles
  -Wl,--no-undefined
  -Wl,-Bstatic
  -Wl,-Bsymbolic
  -Wl,--export-dynamic
  -Wl,-pie
  -Wl,--build-id
  -Wl,-z,noexecstack
  -Wl,-z,now
  -L\${libdir}/openenclave/enclave
  -loeenclave
  -loecrypto)

if (OE_PREFIX_MBEDTLS_SYMBOLS)
  list(APPEND ENCLAVE_CLIBS_1
    -loembedx509
    -loembedcrypto)
else()
  list(APPEND ENCLAVE_CLIBS_1
    -lmbedx509
    -lmbedcrypto)
endif()

list(APPEND ENCLAVE_CLIBS_1 -loecrypto)

set(ENCLAVE_CLIBS_2 -loelibc -loecore)

set(ENCLAVE_CLIBS_LIST ${ENCLAVE_CLIBS_1} ${ENCLAVE_CLIBS_2})
list(JOIN ENCLAVE_CLIBS_LIST " " ENCLAVE_CLIBS)

set(ENCLAVE_CXXLIBS_LIST ${ENCLAVE_CLIBS_1} -loelibcxx ${ENCLAVE_CLIBS_2})
list(JOIN ENCLAVE_CXXLIBS_LIST " " ENCLAVE_CXXLIBS)

##==============================================================================
##
## Host compiler flags:
##
##==============================================================================

set(HOST_INCLUDES "-I\${includedir}")

set(HOST_CFLAGS_CLANG_LIST -fstack-protector-strong ${SPECTRE_MITIGATION_FLAGS})
list(JOIN HOST_CFLAGS_CLANG_LIST " " HOST_CFLAGS_CLANG)

set(HOST_CXXFLAGS_CLANG ${HOST_CFLAGS_CLANG})

set(HOST_CFLAGS_GCC_LIST -fstack-protector-strong -D_FORTIFY_SOURCE=2)
list(JOIN HOST_CFLAGS_GCC_LIST " " HOST_CFLAGS_GCC)

set(HOST_CXXFLAGS_GCC ${HOST_CFLAGS_GCC})

##==============================================================================
##
## Host linker flags:
##
##==============================================================================

if(USE_LIBSGX)
    set(SGX_LIBS "-lsgx_enclave_common -lsgx_dcap_ql -lsgx_urts")
else()
    set(SGX_LIBS "")
endif()

set(HOST_CLIBS "-rdynamic -Wl,-z,noexecstack -L\${libdir}/openenclave/host -loehost -ldl -lpthread ${SGX_LIBS}")

set(HOST_CXXLIBS "${HOST_CLIBS}")

##==============================================================================
##
## oeenclave-gcc.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-gcc.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-gcc.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-gcc.pc
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oeenclave-g++.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-g++.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-g++.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-g++.pc
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oehost-gcc.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost-gcc.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-gcc.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-gcc.pc
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oehost-g++.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost-g++.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-g++.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-g++.pc
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oeenclave-clang.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-clang.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang.pc
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oeenclave-clang++.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-clang++.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang++.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave-clang++.pc
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oehost-clang.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost-clang.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-clang.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-clang.pc
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## oehost-clang++.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost-clang++.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-clang++.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost-clang++.pc
    DESTINATION
    "${CMAKE_INSTALL_DATADIR}/pkgconfig")

##==============================================================================
##
## Reconfigure .pc files so that samples and tests may use them.
##
##==============================================================================

# TODO: Remove this work-around after we make the pkg-config files relocatable.
set(PREFIX "$OE_PREFIX")

set(ENCLAVE_CINCLUDES
    "-I\${includedir}/openenclave/3rdparty/libc -I\${includedir}/openenclave/3rdparty -I\${includedir}")

set(ENCLAVE_CXXINCLUDES
    "-I\${includedir}/openenclave/3rdparty/libcxx ${ENCLAVE_CINCLUDES}")


configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-gcc.pc
    ${CMAKE_BINARY_DIR}/pkgconfig/oeenclave-gcc.pc
    @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-g++.pc
    ${CMAKE_BINARY_DIR}/pkgconfig/oeenclave-g++.pc
    @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost-gcc.pc
    ${CMAKE_BINARY_DIR}/pkgconfig/oehost-gcc.pc
    @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost-g++.pc
    ${CMAKE_BINARY_DIR}/pkgconfig/oehost-g++.pc
    @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-clang.pc
    ${CMAKE_BINARY_DIR}/pkgconfig/oeenclave-clang.pc
    @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave-clang++.pc
    ${CMAKE_BINARY_DIR}/pkgconfig/oeenclave-clang++.pc
    @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost-clang.pc
    ${CMAKE_BINARY_DIR}/pkgconfig/oehost-clang.pc
    @ONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost-clang++.pc
    ${CMAKE_BINARY_DIR}/pkgconfig/oehost-clang++.pc
    @ONLY)
