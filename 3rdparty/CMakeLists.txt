# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Note: order does matter
if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
  # While we enable -Werror globally in our CMake build, we do not 
  # want to fix all the warnings in third-party code. Thus we disable it here by adding 
  # -Wno-error for all targets under this folder
  add_compile_options(-Wno-error)
endif()

add_subdirectory(libcxx)
add_subdirectory(libcxxrt)
add_subdirectory(libunwind)
add_subdirectory(musl)
add_subdirectory(mbedtls) # after musl
