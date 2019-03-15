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

set(ENCLAVE_CFLAGS_CLANG
    "-nostdinc -m64 -fPIE -ftls-model=local-exec -mllvm -x86-speculative-load-hardening")

set(ENCLAVE_CFLAGS_GCC
    "-nostdinc -m64 -fPIE -ftls-model=local-exec")

##==============================================================================
##
## Enclave linker flags:
##
##==============================================================================

string(APPEND ENCLAVE_CLIBS_1 "-nostdlib ")
string(APPEND ENCLAVE_CLIBS_1 "-nodefaultlibs ")
string(APPEND ENCLAVE_CLIBS_1 "-nostartfiles ")
string(APPEND ENCLAVE_CLIBS_1 "-Wl,--no-undefined ")
string(APPEND ENCLAVE_CLIBS_1 "-Wl,-Bstatic ")
string(APPEND ENCLAVE_CLIBS_1 "-Wl,-Bsymbolic ")
string(APPEND ENCLAVE_CLIBS_1 "-Wl,--export-dynamic ")
string(APPEND ENCLAVE_CLIBS_1 "-Wl,-pie ")
string(APPEND ENCLAVE_CLIBS_1 "-Wl,--build-id ")
string(APPEND ENCLAVE_CLIBS_1 "-L\${libdir}/openenclave/enclave ")
string(APPEND ENCLAVE_CLIBS_1 "-loeenclave ")
string(APPEND ENCLAVE_CLIBS_1 "-lmbedx509 ")
string(APPEND ENCLAVE_CLIBS_1 "-lmbedcrypto ")

string(APPEND ENCLAVE_CLIBS_2 "-loelibc ")
string(APPEND ENCLAVE_CLIBS_2 "-loecore ")

set(ENCLAVE_CLIBS "${ENCLAVE_CLIBS_1} ${ENCLAVE_CLIBS_2}")

set(ENCLAVE_CXXLIBS "${ENCLAVE_CLIBS_1} -loelibcxx ${ENCLAVE_CLIBS_2}")

##==============================================================================
##
## Host compiler flags:
##
##==============================================================================

set(HOST_INCLUDES "-I\${includedir}")

set(HOST_CFLAGS_CLANG "-mllvm -x86-speculative-load-hardening")

set(HOST_CXXFLAGS_CLANG "${HOST_CFLAGS_CLANG}")

set(HOST_CFLAGS_GCC "")

set(HOST_CXXFLAGS_GCC "${HOST_CFLAGS_GCC}")

##==============================================================================
##
## Host linker flags:
##
##==============================================================================

if(USE_LIBSGX)
    set(SGX_LIBS "-lsgx_enclave_common -lsgx_dcap_ql -lsgx_urts")
endif()

set(HOST_CLIBS "-rdynamic -L\${libdir}/openenclave/host -loehost -ldl -lpthread ${SGX_LIBS}")

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

