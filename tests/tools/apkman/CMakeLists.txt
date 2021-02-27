# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# apkman currently works only on Linux.
if (NOT UNIX)
  return()
endif ()

# LVI mitigation build requires -lvi-cfg suffixed libraries.
# Libraries from apkman are not lvi mitigated and don't have such suffix.
# Disable testing under LVI.
if (NOT ${LVI_MITIGATION} MATCHES "None")
  return()
endif ()

# Create an imported executable for use by tests.
add_executable(apkman IMPORTED)
set_target_properties(
  apkman PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/tools/apkman/apkman)

execute_process(COMMAND ${PROJECT_SOURCE_DIR}/tools/apkman/apkman help
                        COMMAND_ERROR_IS_FATAL ANY)

# Fetch apkman root folder for accessing includes and libraries.
execute_process(
  COMMAND ${PROJECT_SOURCE_DIR}/tools/apkman/apkman root COMMAND_ERROR_IS_FATAL
          ANY OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE APKMAN_ROOT)

# Ensure that apkman is initialized.
add_custom_target(
  apkman-init # Setup so that packages can be built from source.
  COMMAND apkman add build-base clang gdb cmake git
  COMMAND apkman --wrap-ld)

# Testing utilities.
add_subdirectory(utils)

# C library tests.
add_subdirectory(libs)

# C++ library tests.
add_subdirectory(cpp)

# Language runtimes.
add_subdirectory(runtimes)
