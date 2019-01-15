# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (WIN32)
  # NOTE: On Windows we have found that we must use Git Bash, not the
  # Bash from the Windows Subsystem for Linux. Hence this is
  # explicitly searching only for Git Bash. See #1302 for more.
  find_program(GIT git)
  get_filename_component(GIT_DIR ${GIT} DIRECTORY)
  find_program(BASH bash
    PATHS "C:/Program Files/Git/bin" "${GIT_DIR}/../bin"
    NO_DEFAULT_PATH) # Do not find WSL bash.

  if (NOT BASH)
    message(FATAL_ERROR "Git Bash not found!")
  endif ()
else ()
  find_program(BASH bash)
  if (NOT BASH)
    message(FATAL_ERROR "Bash not found!")
  endif ()
endif ()

add_subdirectory(libcxx)
add_subdirectory(libcxxrt)
add_subdirectory(libunwind)
add_subdirectory(musl)
add_subdirectory(mbedtls) # after musl
