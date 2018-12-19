# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy MUSL headers to collector dir and wrap
# actual compilation and lib-generation happens in <ROOT>/libc/

if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  set(ARCH "x86_64")
else()
  set(ARCH "aarch64")
endif()

set(CFLAGS "-fPIC -DSYSCALL_NO_INLINE")
set(PATCHES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/patches)
set(MUSL_DIR ${CMAKE_CURRENT_BINARY_DIR}/musl)
set(MUSL_INCLUDES ${OE_INCDIR}/openenclave/libc)

include (ExternalProject)
ExternalProject_Add(musl_includes
  DOWNLOAD_COMMAND
    ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_CURRENT_LIST_DIR}/musl
    ${CMAKE_CURRENT_BINARY_DIR}/musl
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
    ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/musl
    ./configure
      --includedir=${MUSL_INCLUDES}
      CFLAGS=${CFLAGS}
      CC=${CMAKE_C_COMPILER}
      CXX=${CMAKE_CXX_COMPILER}
  BUILD_COMMAND
    ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/musl
    make install-headers
    COMMAND ${CMAKE_COMMAND} -E copy
      ${MUSL_INCLUDES}/endian.h
      ${MUSL_INCLUDES}/__endian.h
    COMMAND ${CMAKE_COMMAND} -E copy
      ${PATCHES_DIR}/endian.h
      ${MUSL_INCLUDES}/endian.h

    # Append deprecations.h to all C header files.
    COMMAND ${CMAKE_CURRENT_LIST_DIR}/append-deprecations
      ${MUSL_INCLUDES}

    # Copy local deprecations.h to include/bits/deprecated.h.
    COMMAND ${CMAKE_COMMAND} -E copy
      ${CMAKE_CURRENT_LIST_DIR}/deprecations.h
      ${MUSL_INCLUDES}/bits/deprecations.h

  BUILD_BYPRODUCTS
    ${MUSL_INCLUDES} ${CMAKE_CURRENT_BINARY_DIR}/musl

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
