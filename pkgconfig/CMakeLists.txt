# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## Set OE_VERSION to contents of file.
##
##==============================================================================

file(STRINGS "../VERSION" OE_VERSION)

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
    "-I\${includedir}/libc -I\${includedir}")

set(ENCLAVE_CXXINCLUDES 
    "-I\${includedir}/libcxx ${ENCLAVE_CINCLUDES}")

set(ENCLAVE_CFLAGS_CLANG 
    "-nostdinc -m64 -fPIC -mllvm -x86-speculative-load-hardening")

set(ENCLAVE_CFLAGS_GCC 
    "-nostdinc -m64 -fPIC")

##==============================================================================
##
## Enclave linker flags:
##
##==============================================================================

set(ENCLAVE_CLIBS_1 "-nostdlib -nodefaultlibs -nostartfiles -Wl,--no-undefined -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -L\${libdir}/openenclave/enclave -loeenclave -lmbedx509 -lmbedcrypto")

set(ENCLAVE_CLIBS_2 "-loelibc -loecore")

set(ENCLAVE_CLIBS "${ENCLAVE_CLIBS_1} ${ENCLAVE_CLIBS_2}")

set(ENCLAVE_CXXLIBS "${ENCLAVE_CLIBS_1} -loelibcxx ${ENCLAVE_CLIBS_2}")

##==============================================================================
##
## Host compiler flags:
##
##==============================================================================

set(HOST_INCLUDES "-I\${includedir}")

set(HOST_CFLAGS_CLANG "-mllvm -x86-speculative-load-hardening")

set(HOST_CFLAGS_GCC "")

##==============================================================================
##
## Host linker flags:
##
##==============================================================================

if(USE_LIBSGX)
    set(SGX_LIBS "-lsgx_enclave_common -lsgx_ngsa_ql -lsgx_urts_ng")
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
    /usr/local/share/pkgconfig)

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
    /usr/local/share/pkgconfig)

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
    /usr/local/share/pkgconfig)

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
    /usr/local/share/pkgconfig)

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
    /usr/local/share/pkgconfig)

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
    /usr/local/share/pkgconfig)

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
    /usr/local/share/pkgconfig)

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
    /usr/local/share/pkgconfig)

##==============================================================================
##
## Reconfigure .pc files so that samples and tests may use them.
##
##==============================================================================

set(PREFIX "${CMAKE_BINARY_DIR}/output")

set(ENCLAVE_CINCLUDES 
    "-I\${includedir}/openenclave/libc -I\${includedir} -I${PROJECT_SOURCE_DIR}/include")

set(ENCLAVE_CXXINCLUDES 
    "-I\${includedir}/openenclave/libcxx ${ENCLAVE_CINCLUDES}")

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

