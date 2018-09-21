# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Top-level CMake file for the Open Enclave SDK
#
# Please read The Ultimate Guide to CMake:
# https://rix0r.nl/blog/2015/08/13/cmake-guide/
cmake_minimum_required(VERSION 3.5.1 FATAL_ERROR)

# Read version from "VERSION" file.
file(STRINGS "VERSION" OE_VERSION)

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

# See `cmake/compiler_settings.cmake` for all compiler settings
include(compiler_settings)

# Set default paths
# TODO: Set this up properly and move to separate file
include(GNUInstallDirs)
set(OE_OUTPUT_DIR ${PROJECT_BINARY_DIR}/output CACHE INTERNAL "Path to the intermittent collector tree")
set(OE_BINDIR ${OE_OUTPUT_DIR}/bin CACHE INTERNAL "Binary collector")
set(OE_DATADIR ${OE_OUTPUT_DIR}/share CACHE INTERNAL "Data collector root")
set(OE_DOCDIR ${OE_OUTPUT_DIR}/share/doc CACHE INTERNAL "Doc collector root")
set(OE_INCDIR ${OE_OUTPUT_DIR}/include CACHE INTERNAL "Include collector")
set(OE_LIBDIR ${OE_OUTPUT_DIR}/lib CACHE INTERNAL "Library collector")

# Generate config files for consumers using Make
include(gen_config_file)
gen_config_file(${OE_DATADIR}/openenclave/config.mak "${CMAKE_INSTALL_PREFIX}")
install(FILES ${OE_DATADIR}/openenclave/config.mak
  DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples)
install(FILES ${OE_DATADIR}/openenclave/config.mak
  DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave)

# Generate and install CMake export file for consumers using Cmake
include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${PROJECT_SOURCE_DIR}/cmake/openenclave-config.cmake.in
  ${CMAKE_BINARY_DIR}/cmake/openenclave-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake)
write_basic_package_version_file(
  ${CMAKE_BINARY_DIR}/cmake/openenclave-config-version.cmake
  COMPATIBILITY SameMajorVersion)
install(
  FILES ${CMAKE_BINARY_DIR}/cmake/openenclave-config.cmake
  ${CMAKE_BINARY_DIR}/cmake/openenclave-config-version.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake)
install(
  EXPORT openenclave-targets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
  FILE openenclave-targets.cmake)

# CPack package handling
include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Open Enclave SDK")
set(CPACK_PACKAGE_CONTACT "openenclave@microsoft.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${OE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsgx-enclave-common (>=2.3.100.46354-1), libsgx-enclave-common-dev (>=2.3.100.0-1), libsgx-dcap-ql (>=1.0.100.46460-1.0), libsgx-dcap-ql-dev (>=1.0.100.46460-1.0)")
include(CPack)

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

if (UNIX)
  add_subdirectory(3rdparty)
  add_subdirectory(debugger)
  add_subdirectory(docs/refman)
  add_subdirectory(enclave)
  add_subdirectory(enclave/core)
  add_subdirectory(libc)
  add_subdirectory(libcxx)
  add_subdirectory(pkgconfig)
  add_subdirectory(samples)
  add_subdirectory(tools)
endif ()
