# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Compile CXXRT

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-tautological-compare")

# build cxxrt sources passing additional options
add_subdirectory(libcxxrt/src)
target_compile_options(cxxrt-static PRIVATE
    -fPIC
    # cannot use add_link_libraries on out-of-dir target
    -nostdinc $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>
    -I${OE_INCDIR}/openenclave/libc
    )
add_dependencies(cxxrt-static oelibc_includes)
