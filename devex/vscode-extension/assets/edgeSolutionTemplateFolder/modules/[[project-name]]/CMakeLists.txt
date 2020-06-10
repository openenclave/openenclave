# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(
  "[[project-name]]"
  VERSION 1.0
  LANGUAGES C CXX)

set(OE_TEE
    ""
    CACHE STRING "Select a Trusted Execution Environment (TEE) implementation.")
set_property(CACHE OE_TEE PROPERTY STRINGS "SGX" "OP-TEE")

set(OE_OPTEE_PLATFORM CACHE STRING "Select the target OP-TEE platform")
set_property(CACHE OE_OPTEE_PLATFORM PROPERTY STRINGS "Grapeboard" "QEMU-ARMv8")

if ("${OE_TEE}" STREQUAL "SGX")
  set(OE_SGX ON)
  set(OE_OPTEE OFF)
elseif ("${OE_TEE}" STREQUAL "OP-TEE")
  set(OE_SGX OFF)
  set(OE_OPTEE ON)
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

string(TOUPPER ${CMAKE_BUILD_TYPE} OE_BUILD_TYPE)
if ("${OE_BUILD_TYPE}" STREQUAL "DEBUG")
  set(OE_DEBUG ON)
else ()
  set(OE_DEBUG OFF)
endif ()

find_package(OpenEnclave CONFIG REQUIRED)

list(APPEND CMAKE_MODULE_PATH "cmake")

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/lib)

add_subdirectory(enc)
add_subdirectory(host)
