# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy libunwind sources and build out-of-tree

string(CONCAT CFLAGS
    "-Wall "
    "-Werror "
    "-Wno-pointer-to-int-cast "
    "-Wno-unused-function "
    "-Wno-unused-variable "
    "-Wno-cpp "
    "-fno-builtin "
    "-fPIC "
    "-include ${CMAKE_CURRENT_SOURCE_DIR}/stubs.h "
    "-I${PROJECT_SOURCE_DIR}/include "
    "${SPECTRE_MITIGATION_FLAGS} ")

if (CMAKE_C_COMPILER_ID MATCHES "GNU")
    string(CONCAT CFLAGS
        ${CFLAGS}
        "-Wno-unused-but-set-variable "
        "-Wno-maybe-uninitialized ")
elseif (CMAKE_C_COMPILER_ID MATCHES "Clang")
    string(CONCAT CFLAGS 
        ${CFLAGS}
        "-Wno-header-guard "
        "-Wno-uninitialized "
        "-Wno-unused-variable ")
endif()

set(OPTS
    --enable-shared=no
    --disable-block-signals
    --enable-cxx-exceptions
    # Note that the C compiler is used for ASM as well.
    CC=${CMAKE_C_COMPILER}
    CXX=${CMAKE_CXX_COMPILER}
    )

string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE)

if ((BUILD_TYPE STREQUAL "DEBUG") OR (BUILD_TYPE STREQUAL "RELWITHDEBINFO"))
    list(APPEND OPTS "--enable-debug=yes" "--enable-debug-frame==yes")
    set(CFLAGS "${CFLAGS} -g")
else()
    list (APPEND OPTS "--enable-debug=no" "--enable-debug-frame==no")
endif()

include (ExternalProject)

ExternalProject_Add(oelibcxx_unwind

    # Copy libunwind source tree to build directory.
    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/libunwind 
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind

    # Remove -Wall as this is applied too late and will override -Wno-* flags in Clang.
    # Instead we apply it ourselves using CFLAGS (see above).
    COMMAND sed -e "s/-Wall//g"
        ${CMAKE_CURRENT_LIST_DIR}/libunwind/configure.ac >
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/configure.ac

    # Generate autoconf scripts and run configure.
    CONFIGURE_COMMAND cd ${CMAKE_CURRENT_BINARY_DIR}/libunwind && 
        ./autogen.sh "--enable-minidebuginfo=no ${OPTS}" "CFLAGS=${CFLAGS}"

    # Copy libunwind-common.h to libunwind-common.inc.
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/include/libunwind-common.h
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/include/libunwind-common.inc

    # Copy libunwind-common.h to the build directory (this file includes
    # libunwind-common.inc).
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_LIST_DIR}/libunwind-common.h
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/include/libunwind-common.h

    # Copy Gstep.c to Gstep.inc.
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_LIST_DIR}/libunwind/src/x86_64/Gstep.c
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gstep.inc

    # Copy Gstep.c to the the build directory.
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_LIST_DIR}/Gstep.c
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gstep.c

    # Copy Gtrace.c to Gtrace.inc while removing the line containing
    # "static __thread".
    COMMAND grep -v "^static __thread"
        ${CMAKE_CURRENT_LIST_DIR}/libunwind/src/x86_64/Gtrace.c >
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gtrace.inc

    # Copy Gtrace.c to the the build directory.
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_LIST_DIR}/Gtrace.c
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gtrace.c

    # Copy setcontext.S over the one in the build directory.
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_LIST_DIR}/setcontext.S
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/setcontext.S

    # Build libunwind.
    BUILD_COMMAND $(MAKE) -C ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src

    # Empty install command.
    INSTALL_COMMAND "")
