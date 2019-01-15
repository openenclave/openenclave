# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Note: order does matter

if (WIN32)
  find_program(
       BASH
       NAMES bash
       PATHS "C:/Program Files/Git/bin"
       NO_DEFAULT_PATH
   )
   if (NOT BASH)
      message(FATAL_ERROR "Git Bash not found! Please install Git in C:/Program Files/Git/bin")
   endif()
else()
  find_program(BASH bash)
   if (NOT BASH)
      message(FATAL_ERROR "Bash not found!")
   endif()
endif()
message("BASH is set to ${BASH}")

add_subdirectory(libcxx)
add_subdirectory(libcxxrt)
add_subdirectory(libunwind)
add_subdirectory(musl)
add_subdirectory(mbedtls) # after musl
