# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Copy MUSL headers to collector dir and wrap
# actual compilation and lib-generation happens in <ROOT>/libc/

if (OE_SGX)
  set(ARCH "x86_64")
else ()
  set(ARCH "aarch64")
endif ()

# NOTE: MUSL is NOT built by the `ExternalProject_Add` command. These
# C flags only apply to a configuration step that generates the MUSL
# headers. These headers are then turned into an interface library
# `oelibc_includes` below, which compilation options can be applied to
# in order to e.g. ignore warnings.
#
# The build command here is just a set of copy instructions to setup
# `oelibc_includes`. See that CMake target for compile options.
if (OE_SGX)
  set(MUSL_CFLAGS "-DSYSCALL_NO_INLINE -ftls-model=local-exec")
elseif (OE_TRUSTZONE)
  set(MUSL_CFLAGS "-DSYSCALL_NO_INLINE")
endif ()
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

include(ExternalProject)
ExternalProject_Add(
  musl_includes
  DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
                   ${CMAKE_CURRENT_LIST_DIR}/musl ${MUSL_DIR}
  PATCH_COMMAND
  COMMAND ${CMAKE_COMMAND} -E copy ${MUSL_DIR}/arch/${ARCH}/syscall_arch.h
          ${MUSL_DIR}/arch/${ARCH}/__syscall_arch.h
  COMMAND ${CMAKE_COMMAND} -E copy ${MUSL_DIR}/arch/generic/fp_arch.h
          ${MUSL_DIR}/src/include/fp_arch.h
  COMMAND ${CMAKE_COMMAND} -E copy ${PATCHES_DIR}/syscall.h
          ${MUSL_DIR}/src/internal/syscall.h
  COMMAND ${CMAKE_COMMAND} -E copy ${PATCHES_DIR}/syscall_arch.h
          ${MUSL_DIR}/arch/${ARCH}/syscall_arch.h
  COMMAND ${CMAKE_COMMAND} -E copy ${PATCHES_DIR}/pthread_${ARCH}.h
          ${MUSL_DIR}/arch/${ARCH}/pthread_arch.h
  COMMAND ${CMAKE_COMMAND} -E copy ${PATCHES_DIR}/setjmp.h
          ${MUSL_DIR}/include/setjmp.h
  COMMAND ${CMAKE_COMMAND} -E copy ${PATCHES_DIR}/execinfo.h
          ${MUSL_DIR}/include/execinfo.h
  CONFIGURE_COMMAND
    ${CMAKE_COMMAND} -E chdir ${MUSL_DIR} ${OE_BASH} -x ./configure
    --includedir=${MUSL_INCLUDES} CFLAGS=${MUSL_CFLAGS} CC=${MUSL_CC}
    CXX=${MUSL_CXX}
  BUILD_COMMAND
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${MUSL_DIR}/include
          ${MUSL_INCLUDES}
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${MUSL_DIR}/arch/generic/bits
          ${MUSL_INCLUDES}/bits
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${MUSL_DIR}/arch/${ARCH}/bits
          ${MUSL_INCLUDES}/bits
  # bash -c requires the command string to be in a single line
  COMMAND
    ${OE_BASH} -c
    "sed -f ${MUSL_DIR}/tools/mkalltypes.sed ${MUSL_DIR}/arch/${ARCH}/bits/alltypes.h.in ${MUSL_DIR}/include/alltypes.h.in > ${MUSL_INCLUDES}/bits/alltypes.h"
  COMMAND ${CMAKE_COMMAND} -E copy ${MUSL_DIR}/arch/${ARCH}/bits/syscall.h.in
          ${MUSL_INCLUDES}/bits/syscall.h
  # bash -c requires the command string to be in a single line
  COMMAND
    ${OE_BASH} -c
    "sed -n -e s/__NR_/SYS_/p < ${MUSL_DIR}/arch/${ARCH}/bits/syscall.h.in >> ${MUSL_INCLUDES}/bits/syscall.h"
  COMMAND ${CMAKE_COMMAND} -E copy ${MUSL_INCLUDES}/endian.h
          ${MUSL_INCLUDES}/__endian.h
  COMMAND ${CMAKE_COMMAND} -E copy ${PATCHES_DIR}/endian.h
          ${MUSL_INCLUDES}/endian.h
  # Append deprecations.h to all C header files.
  COMMAND ${OE_BASH} -c "${MUSL_APPEND_DEPRECATIONS}"
  # Copy local deprecations.h to include/bits/deprecated.h.
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/deprecations.h
          ${MUSL_INCLUDES}/bits/deprecations.h
  BUILD_BYPRODUCTS ${MUSL_INCLUDES} ${MUSL_DIR}
  INSTALL_COMMAND "")

set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${MUSL_INCLUDES}
                                ${MUSL_DIR})

add_library(oelibc_includes INTERFACE)

add_dependencies(oelibc_includes musl_includes)

# NOTE: The `libcxx` headers are added to this target, not `libcxx`
# itself, so that the correct ordering is enforced. See
# `../libcxxrt/CMakeLists.txt` for the target.
#
# In particular, the headers found in `libcxx` utilize an unfortunate
# GNU pre-processor extension, `#include_next`, which forces an order
# on the include paths. It means that `-Ilibcxx` must come before
# `-Ilibc`, and the least troublesome way to do this in CMake is to
# explicitly add them to the same target. We previously accomplished
# this by setting the `libc` headers as `SYSTEM` headers, but this
# approach broke down in the exported CMake package.
#
# TODO: Perhaps give this a less misleading name as it includes both C
# and C++ headers (but the latter only when the language is C++).
target_include_directories(
  oelibc_includes
  INTERFACE
    $<BUILD_INTERFACE:$<$<COMPILE_LANGUAGE:CXX>:${LIBCXX_INCLUDES}>>
    $<INSTALL_INTERFACE:$<$<COMPILE_LANGUAGE:CXX>:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty/libcxx>>
    $<BUILD_INTERFACE:${MUSL_INCLUDES}>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty/libc>
)

if (CMAKE_C_COMPILER_ID MATCHES GNU AND CMAKE_C_COMPILER_VERSION
                                        VERSION_GREATER_EQUAL "7.1.0")
  # NOTE: This disables a warning that is only present with newer
  # versions of GCC on Ubuntu 18.04.
  target_compile_options(oelibc_includes INTERFACE -Wno-implicit-fallthrough)
endif ()

install(TARGETS oelibc_includes EXPORT openenclave-targets)

install(DIRECTORY ${MUSL_INCLUDES}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/3rdparty)
