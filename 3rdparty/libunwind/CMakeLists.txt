# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy libunwind sources and build out-of-tree

set (OELIBCXX_UNWIND_OPTS
    --enable-shared=no
    --disable-block-signals
    --enable-debug=no
    --enable-debug-frame==no
    --enable-cxx-exceptions
    )

set (OELIBCXX_UNWIND_CFLAGS
    "-DUNW_LOCAL_ONLY -DWSIZE=8 -fno-builtin -fPIC -DOPEN_ENCLAVE -include ${CMAKE_CURRENT_SOURCE_DIR}/stubs.h"
    )

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
