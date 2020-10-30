# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

if (LVI_MITIGATION MATCHES ControlFlow)
  # Configure CMake to use customized compilation toolchain.
  # This package has to be added before `project()`.
  find_package(OpenEnclave-LVI-Mitigation CONFIG REQUIRED)
endif ()

# Provide an option to select the target TEE.
set(OE_TEE
    ""
    CACHE STRING "Select a Trusted Execution Environment (TEE) implementation.")
set_property(CACHE OE_TEE PROPERTY STRINGS "SGX" "OP-TEE")

# Provide an option to select the OP-TEE platform.
set(OE_OPTEE_PLATFORM CACHE STRING "Select the target OP-TEE platform")
set_property(CACHE OE_OPTEE_PLATFORM PROPERTY STRINGS "Grapeboard" "QEMU-ARMv8")

# Set internal convenience flags.
if ("${OE_TEE}" STREQUAL "SGX")
  set(OE_SGX ON)
  set(OE_OPTEE OFF)
  set(OE_EDL_REL_PATH "sgx")
elseif ("${OE_TEE}" STREQUAL "OP-TEE")
  set(OE_SGX OFF)
  set(OE_OPTEE ON)
  set(OE_EDL_REL_PATH "optee")
else ()
  message(FATAL_ERROR "OE_TEE must be one of 'SGX' or 'OP-TEE'.")
endif ()

if (OE_OPTEE)
  if ("${OE_OPTEE_PLATFORM}" STREQUAL "QEMU-ARMv8")
    set(OE_OPTEE_QEMU_ARMV8 ON)
    set(OE_OPTEE_GRAPEBOARD OFF)
  elseif ("${OE_OPTEE_PLATFORM}" STREQUAL "Grapeboard")
    set(OE_OPTEE_QEMU_ARMV8 OFF)
    set(OE_OPTEE_GRAPEBOARD ON)
  else ()
    message(
      FATAL_ERROR
        "OE_OPTEE_PLATFORM must be one of 'QEMU-ARMv8' or 'Grapeboard'.")
  endif ()
endif ()

# Use the installed SDK build for SGX, or the build bundled into this project
# via the VS Code extension for OP-TEE.
if (OE_OPTEE)
  set(OE_PACKAGE_PREFIX ${CMAKE_SOURCE_DIR}/devkit/sdk/optee)

  if (OE_OPTEE_QEMU_ARMV8)
    set(OE_PACKAGE_OPTEE_PLATFORM vexpress-qemu_armv8a)
  elseif (OE_OPTEE_GRAPEBOARD)
    set(OE_PACKAGE_OPTEE_PLATFORM ls-ls1012grapeboard)
  endif ()

  set(OpenEnclave_DIR
      ${OE_PACKAGE_PREFIX}/${OE_PACKAGE_OPTEE_PLATFORM}/lib/openenclave/cmake)
endif ()

project(
  "[[project-name]]"
  VERSION 1.0
  LANGUAGES C CXX)

string(TOUPPER ${CMAKE_BUILD_TYPE} OE_BUILD_TYPE)
if ("${OE_BUILD_TYPE}" STREQUAL "DEBUG")
  set(OE_DEBUG ON)
else ()
  set(OE_DEBUG OFF)
endif ()

# Include the Open Enclave SDK CMake package from the selected prefix.
find_package(OpenEnclave CONFIG REQUIRED)

list(APPEND CMAKE_MODULE_PATH "cmake")

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/lib)

add_subdirectory(enc)
add_subdirectory(host)
