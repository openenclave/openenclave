# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Compile CXXRT

# build cxxrt sources passing additional options
add_subdirectory(libcxxrt/src)
target_compile_options(cxxrt-static PRIVATE
    -include ${CMAKE_CURRENT_SOURCE_DIR}/stubs.h
    -fPIC
    # cannot use add_link_libraries on out-of-dir target
    -nostdinc -nostdinc++
    -I${OE_INCDIR}/openenclave/libc
    )
add_dependencies(cxxrt-static oelibc_includes)
