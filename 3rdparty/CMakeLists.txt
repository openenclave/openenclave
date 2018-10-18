# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Note: order does matter

if (UNIX)
add_subdirectory(libcxx)
add_subdirectory(libcxxrt)
add_subdirectory(libunwind)
add_subdirectory(musl)
endif()

add_subdirectory(mbedtls) # after musl
