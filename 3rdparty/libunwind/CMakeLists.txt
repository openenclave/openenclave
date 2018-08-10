# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy libunwind sources and build out-of-tree

set (OELIBCXX_UNWIND_OPTS
    --enable-shared=no
    --disable-block-signals
    --enable-cxx-exceptions
    # Note that the C compiler is used for ASM as well.
    CC=${CMAKE_C_COMPILER}
    )

set (OELIBCXX_UNWIND_CFLAGS
    "-DWSIZE=8 -fno-builtin -fPIC -DOPEN_ENCLAVE -include ${CMAKE_CURRENT_SOURCE_DIR}/stubs.h"
    )

string(TOUPPER "${CMAKE_BUILD_TYPE}" uppercase_CMAKE_BUILD_TYPE)
if ((uppercase_CMAKE_BUILD_TYPE STREQUAL "DEBUG") OR (uppercase_CMAKE_BUILD_TYPE STREQUAL "RELWITHDEBINFO"))
    list (APPEND OELIBCXX_UNWIND_OPTS "--enable-debug=yes" "--enable-debug-frame==yes")

    set (OELIBCXX_UNWIND_CFLAGS "${OELIBCXX_UNWIND_CFLAGS} -g")
else()
    list (APPEND OELIBCXX_UNWIND_OPTS "--enable-debug=no" "--enable-debug-frame==no")
endif()

include (ExternalProject)
ExternalProject_Add(oelibcxx_unwind
    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/libunwind ${CMAKE_CURRENT_BINARY_DIR}/libunwind
    CONFIGURE_COMMAND cd ${CMAKE_CURRENT_BINARY_DIR}/libunwind &&
            ./autogen.sh
        COMMAND cd ${CMAKE_CURRENT_BINARY_DIR}/libunwind &&
            ./configure "${OELIBCXX_UNWIND_OPTS}" "CFLAGS=${OELIBCXX_UNWIND_CFLAGS}"
    BUILD_COMMAND $(MAKE) -C ${CMAKE_CURRENT_BINARY_DIR}/libunwind/src
    INSTALL_COMMAND ""
    )
