# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy MUSL headers to collector dir and wrap
# actual compilation and lib-generation happens in <ROOT>/libc/

if (OE_SGX)
  set(ARCH "x86_64")
else()
  set(ARCH "aarch64")
endif()

set(MUSL_CFLAGS "-fPIC -DSYSCALL_NO_INLINE")
set(MUSL_CC ${CMAKE_C_COMPILER})
set(MUSL_CXX ${CMAKE_CXX_COMPILER})

set(PATCHES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/patches)
set(MUSL_DIR ${CMAKE_CURRENT_BINARY_DIR}/musl)
set(MUSL_INCLUDES ${OE_INCDIR}/openenclave/libc)

set(MUSL_APPEND_DEPRECATIONS
  "${CMAKE_CURRENT_LIST_DIR}/append-deprecations ${MUSL_INCLUDES}")
if (USE_CLANGW)
  set(MUSL_CFLAGS "-target x86_64-pc-linux ${MUSL_CFLAGS}")
  set(MUSL_CC clang)
  set(MUSL_CXX clang++)
  set(MUSL_APPEND_DEPRECATIONS "echo 'Deprecations not applied on Windows'")
endif ()

include (ExternalProject)
ExternalProject_Add(musl_includes
  DOWNLOAD_COMMAND
    ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_LIST_DIR}/musl
    ${MUSL_DIR}
  PATCH_COMMAND
    COMMAND ${CMAKE_COMMAND} -E copy
      ${MUSL_DIR}/arch/${ARCH}/syscall_arch.h
      ${MUSL_DIR}/arch/${ARCH}/__syscall_arch.h
    COMMAND ${CMAKE_COMMAND} -E copy
      ${PATCHES_DIR}/syscall_arch.h
      ${MUSL_DIR}/arch/${ARCH}/syscall_arch.h
    COMMAND ${CMAKE_COMMAND} -E copy
      ${PATCHES_DIR}/pthread_arch.h
      ${MUSL_DIR}/arch/${ARCH}/pthread_arch.h
  CONFIGURE_COMMAND
    ${CMAKE_COMMAND} -E chdir ${MUSL_DIR}
    # TODO: Use `find_program` and ensure Bash is available.
    bash -x ./configure
      --includedir=${MUSL_INCLUDES}
      CFLAGS=${MUSL_CFLAGS}
      CC=${MUSL_CC}
      CXX=${MUSL_CXX}
  BUILD_COMMAND
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${MUSL_DIR}/include
        ${MUSL_INCLUDES}
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${MUSL_DIR}/arch/generic/bits
        ${MUSL_INCLUDES}/bits
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${MUSL_DIR}/arch/${ARCH}/bits
        ${MUSL_INCLUDES}/bits
    # bash -c requires the command string to be in a single line
    COMMAND bash -c "sed -f ${MUSL_DIR}/tools/mkalltypes.sed ${MUSL_DIR}/arch/${ARCH}/bits/alltypes.h.in ${MUSL_DIR}/include/alltypes.h.in > ${MUSL_INCLUDES}/bits/alltypes.h"
    COMMAND ${CMAKE_COMMAND} -E copy
        ${MUSL_DIR}/arch/${ARCH}/bits/syscall.h.in
        ${MUSL_INCLUDES}/bits/syscall.h
    # bash -c requires the command string to be in a single line
    COMMAND bash -c "sed -n -e s/__NR_/SYS_/p < ${MUSL_DIR}/arch/${ARCH}/bits/syscall.h.in >> ${MUSL_INCLUDES}/bits/syscall.h"
    COMMAND ${CMAKE_COMMAND} -E copy
      ${MUSL_INCLUDES}/endian.h
      ${MUSL_INCLUDES}/__endian.h
    COMMAND ${CMAKE_COMMAND} -E copy
      ${PATCHES_DIR}/endian.h
      ${MUSL_INCLUDES}/endian.h
    # Append deprecations.h to all C header files.
    COMMAND bash -c "${MUSL_APPEND_DEPRECATIONS}"
    # Copy local deprecations.h to include/bits/deprecated.h.
    COMMAND ${CMAKE_COMMAND} -E copy
      ${CMAKE_CURRENT_LIST_DIR}/deprecations.h
      ${MUSL_INCLUDES}/bits/deprecations.h
  BUILD_BYPRODUCTS
    ${MUSL_INCLUDES} ${MUSL_DIR}
  INSTALL_COMMAND "")

add_library(oelibc_includes INTERFACE)

add_dependencies(oelibc_includes musl_includes)

# NOTE: This is explicitly marked as a `SYSTEM` directory because it
# must be searched last. In particularly, the headers found in
# `libcxx` utilize an unfortunate GNU pre-processor extension,
# `#include_next`, which forces an order on the include paths. It
# means that `-Ilibcxx` must come before `-Ilibc`, and the least
# troublesome way to do this in CMake is set this as a `SYSTEM`
# include path.
target_include_directories(oelibc_includes
  SYSTEM INTERFACE
  $<BUILD_INTERFACE:${MUSL_INCLUDES}>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty/libc>)

install(TARGETS oelibc_includes EXPORT openenclave-targets)

install(DIRECTORY ${MUSL_INCLUDES}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
