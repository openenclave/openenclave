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
## Enclave compiler flags:
##
##==============================================================================

set(ENCLAVE_CFLAGS "-nostdinc -m64 -fPIC -I\${includedir} -I\${includedir}/libc")

set(ENCLAVE_CXXFLAGS "${ENCLAVE_CFLAGS} -I\${includedir}/libcxx")

set(ENCLAVE_CFLAGS_CLANG "${ENCLAVE_CFLAGS} -mllvm -x86-speculative-load-hardening -mxsave")

set(ENCLAVE_CXXFLAGS_CLANG "${ENCLAVE_CXXFLAGS} -mllvm -x86-speculative-load-hardening -mxsave")

set(ENCLAVE_CFLAGS_GCC "${ENCLAVE_CFLAGS}")

set(ENCLAVE_CXXFLAGS_GCC "${ENCLAVE_CXXFLAGS}")

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

set(HOST_CFLAGS "-I\${includedir}")

set(HOST_CFLAGS_CLANG "-mllvm -x86-speculative-load-hardening -mxsave ${HOST_CFLAGS}")

set(HOST_CXXFLAGS_CLANG "${HOST_CFLAGS_CLANG}")

set(HOST_CFLAGS_GCC "${HOST_CFLAGS}")

set(HOST_CXXFLAGS_GCC "${HOST_CFLAGS}")

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

