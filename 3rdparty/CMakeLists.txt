# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# NOTE: This is set here so that both `libcxx` and `musl` can use it
# without setting it twice. This is necessary due to an odd dependency
# between the two targets. See their respective CMake files for more
# details.
set(LIBCXX_INCLUDES ${OE_INCDIR}/openenclave/libcxx)

add_subdirectory(libcxx)
add_subdirectory(libcxxrt)
add_subdirectory(libunwind)
add_subdirectory(musl)
add_subdirectory(mbedtls)
if (OE_TRUSTZONE)
  add_subdirectory(optee/libutee)
endif ()
