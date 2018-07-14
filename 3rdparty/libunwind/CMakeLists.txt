# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy libunwind sources and build out-of-tree

string(CONCAT CFLAGS 
    "-DUNW_LOCAL_ONLY "
    "-DWSIZE=8 "
    "-fno-builtin "
    "-fPIC "
    "-include ${CMAKE_CURRENT_SOURCE_DIR}/stubs.h "
    "-I${PROJECT_SOURCE_DIR}/include ")

set(OPTS
    --enable-shared=no
    --disable-block-signals
    --enable-cxx-exceptions)

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

    # Generate autoconf scripts.
    CONFIGURE_COMMAND cd ${CMAKE_CURRENT_BINARY_DIR}/libunwind && 
        ./autogen.sh

    # Run the ./configure script.
    COMMAND cd ${CMAKE_CURRENT_BINARY_DIR}/libunwind &&
        ./configure "${OPTS}" "CFLAGS=${CFLAGS}"

    # Copy libunwind-common.h to libunwind-commond.h.h
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/include/libunwind-common.h
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/include/libunwind-common.h.h

    # Copy libunwind-common.h to the the build directory.
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_LIST_DIR}/libunwind-common.h
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/include/libunwind-common.h

    # Copy Gstep.c to Gstep.c.h
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gstep.c
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gstep.c.h

    # Copy Gstep.c to the the build directory.
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_LIST_DIR}/Gstep.c
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gstep.c

    # Copy Gtrace.c to Gtrace.c.h
    COMMAND grep -v "^static __thread"
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gtrace.c >
        ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src/x86_64/Gtrace.c.h

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
