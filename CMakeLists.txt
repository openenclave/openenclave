# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Top-level CMake file for the Open Enclave SDK
#
# Please read The Ultimate Guide to CMake:
# https://rix0r.nl/blog/2015/08/13/cmake-guide/
cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

# Read version from "VERSION" file.
file(STRINGS "VERSION" OE_VERSION_WITH_V)
string(REGEX REPLACE "^v" "" OE_VERSION ${OE_VERSION_WITH_V})

# Select the assembler
# TODO: See #755: This should probably be removed
if (UNIX)
  set(OE_ASM ASM)
elseif (WIN32)
  set(OE_ASM ASM_MASM)
endif ()

# Set compiler search order to prefer Clang
# This has to be done before `project`
# http://cmake.3232098.n2.nabble.com/Prefer-clang-over-gcc-td7597742.html
set(CMAKE_C_COMPILER_NAMES clang-7 cc)
set(CMAKE_CXX_COMPILER_NAMES clang++-7 c++)

project("Open Enclave SDK" VERSION ${OE_VERSION} LANGUAGES C CXX ${OE_ASM})

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Collect Git info
if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
  execute_process(
    COMMAND git rev-parse HEAD
    OUTPUT_VARIABLE GIT_COMMIT
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  execute_process(
    COMMAND git symbolic-ref HEAD
    OUTPUT_VARIABLE GIT_BRANCH
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif ()

# Get Jenkins build number
set(BUILD_NUMBER $ENV{BUILD_NUMBER})
if (NOT BUILD_NUMBER)
  set(BUILD_NUMBER "0")
endif ()

# Set the architecture. We do this before the compiler settings, since some
# of them are arch specific.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
    # TODO: Right now assume it's Intel+SGX for x86_64 processors
    set(OE_SGX 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*|ARM.*|aarch64.*|AARCH64.*")
    set(OE_TRUSTZONE 1)
else()
    message(FATAL_ERROR "Unknown processor. Only Intel SGX and ARM TrustZone are supported")
endif()

# See `cmake/compiler_settings.cmake` for all compiler settings
include(compiler_settings)

# See `cmake/package_settings.cmake` for all package settings
include(package_settings)

# See `cmake/add_enclave.cmake` for enclave creation logic
include(add_enclave)

# User configurable options
option(USE_LIBSGX "Build oehost using SGX library requiring FLC" OFF)
if (USE_LIBSGX AND WIN32)
  message(FATAL_ERROR "USE_LIBSGX is not supported on Windows. Disable this when calling cmake with -DUSE_LIBSGX=OFF")
endif ()

# TODO: See #756: Fix this because it is incompatible with
# multi-configuration generators
if (CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
  # In non-win32 debug build, debug_malloc is on by default
  option(USE_DEBUG_MALLOC "Build oeenclave with memory leak detection capability." ON)
else ()
  # In win32 or non-debug builds, debug_malloc is off by default
  option(USE_DEBUG_MALLOC "Build oeenclave with memory leak detection capability." OFF)
endif ()

if (USE_DEBUG_MALLOC AND WIN32)
  message(FATAL_ERROR "USE_DEBUG_MALLOC is not supported on Windows. Disable this when calling cmake with -DUSE_DEBUG_MALLOC=OFF")
endif ()

option(ADD_WINDOWS_ENCLAVE_TESTS "Build Windows enclave tests" OFF)

# Configure testing
enable_testing()
include(add_enclave_test)

# Recurse through subdirectories
add_subdirectory(host)
add_subdirectory(include)
add_subdirectory(tests)
add_subdirectory(tools)

if (UNIX)
  add_subdirectory(3rdparty)
  if (OE_SGX)
      add_subdirectory(debugger)
  endif()
  add_subdirectory(docs/refman)
  add_subdirectory(enclave)
  add_subdirectory(enclave/core)
  add_subdirectory(libc)
  add_subdirectory(libcxx)
  add_subdirectory(pkgconfig)
  add_subdirectory(samples)
endif ()
