# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
#
# Top-level CMake file for the Open Enclave SDK
#
# Please read The Ultimate Guide to CMake:
# https://rix0r.nl/blog/2015/08/13/cmake-guide/
cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

# Utility to ensure specific submodules are present.
function (check_submodule_not_empty path)
  file(GLOB submodule_files "${path}/*")
  list(LENGTH submodule_files number)
  if (${number} EQUAL 0)
    message(
      FATAL_ERROR
        "Submodule ${path} is empty. You can initialize the submodule now with \
         'git submodule update --recursive --init',\
         or during 'git clone' by passing '--recursive'.")
  endif ()
endfunction ()

# Read version from "VERSION" file.
file(STRINGS "VERSION" OE_VERSION_WITH_V)
string(REGEX REPLACE "^v" "" OE_VERSION ${OE_VERSION_WITH_V})

# Temporary fix to account for differences in expected version numbers
# between Debian packages and NuGet packages.
if (WIN32)
  string(REGEX REPLACE "~" "-" OE_VERSION ${OE_VERSION})
endif ()

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

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Will be overwritten during the cmake initialization.
set(LVI_MITIGATION
    "None"
    CACHE STRING "Build with LVI mitigation.")
set(LVI_MITIGATION_BINDIR
    "None"
    CACHE STRING "Path to the LVI mitigation bindir.")
# On Unix, configuring cmake to adopt the customized compilation toolchain for LVI mitigation.
# Note that this has be done before `project`.
if (UNIX AND LVI_MITIGATION MATCHES ControlFlow)
  if (${LVI_MITIGATION_BINDIR} MATCHES None)
    message(FATAL_ERROR "LVI_MITIGATION_BINDIR is not specified.")
  endif ()
  include(configure_lvi_mitigation_build)
  configure_lvi_mitigation_build(BINDIR ${LVI_MITIGATION_BINDIR})
endif ()

project(
  "Open Enclave SDK"
  LANGUAGES C CXX ${OE_ASM}
  HOMEPAGE_URL "https://github.com/openenclave/openenclave")
set(PROJECT_VERSION ${OE_VERSION})
set(OE_SCRIPTSDIR "${PROJECT_SOURCE_DIR}/scripts")

# Collect Git info
if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
  execute_process(
    COMMAND git rev-parse HEAD
    OUTPUT_VARIABLE GIT_COMMIT
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

  execute_process(
    COMMAND git symbolic-ref HEAD
    OUTPUT_VARIABLE GIT_BRANCH
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} ERROR_QUIET
                      OUTPUT_STRIP_TRAILING_WHITESPACE)

  # Install Git pre-commit hook
  file(COPY scripts/pre-commit scripts/commit-msg
       DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
endif ()

# Generates `compile_commands.json` used by some developers. Only
# supported by Makefile and Ninja generators, but is otherwise
# ignored.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Validate CMAKE_BUILD_TYPE
string(TOUPPER "${CMAKE_BUILD_TYPE}" uppercase_CMAKE_BUILD_TYPE)
list(APPEND uppercase_build_type "" "DEBUG" "RELEASE" "RELWITHDEBINFO")
if (NOT uppercase_CMAKE_BUILD_TYPE IN_LIST uppercase_build_type)
  message(FATAL_ERROR "UNKNOWN CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif ()

# Get Jenkins build number
if (DEFINED ENV{BUILD_NUMBER})
  set(BUILD_NUMBER $ENV{BUILD_NUMBER})
else ()
  set(BUILD_NUMBER "0")
endif ()

# Set the architecture. We do this before the compiler settings, since some
# of them are arch specific.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  # TODO: Right now assume it's Intel+SGX for x86_64 processors
  set(OE_SGX 1)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*|ARM.*|aarch64.*|AARCH64.*")
  set(OE_TRUSTZONE 1)
else ()
  message(
    FATAL_ERROR
      "Unknown processor. Only Intel SGX and ARM TrustZone are supported")
endif ()

if (OE_SGX)
  if (WIN32)
    # Building enclaves on windows is on by default but can be disabled for enclaves pre-compiled under linux
    option(BUILD_ENCLAVES "Build ELF enclaves" ON)
  else ()
    set(BUILD_ENCLAVES ON)
  endif ()

  if (BUILD_ENCLAVES AND WIN32)
    # Search for prerequisites
    find_program(CLANG clang)
    if (NOT CLANG)
      message(FATAL_ERROR "Clang is required to build ELF enclaves on Windows")
    endif ()

    # Get the list of clang specific defines and search for __clang_major__
    execute_process(
      COMMAND cmd.exe /c " clang -dM -E -x c nul | findstr __clang_major__ "
      RESULT_VARIABLE HAD_ERROR
      OUTPUT_VARIABLE CONFIG_OUTPUT)
    if (HAD_ERROR)
      message(FATAL_ERROR "Could not parse clang major version")
    endif ()

    # Format the output for a list
    string(REPLACE " " ";" CONFIG_OUTPUT ${CONFIG_OUTPUT})
    # Get the major version for clang
    list(GET CONFIG_OUTPUT 2 MAJOR_VERSION)
    if (MAJOR_VERSION VERSION_LESS 7)
      message(FATAL_ERROR "Clang version 7.0 or higher is required")
    endif ()

    set(USE_CLANGW ON)
  endif ()
else () # NOT OE_SGX
  # On non-sgx enclaves are built by default on Unix
  if (UNIX)
    set(BUILD_ENCLAVES ON)
  endif ()
endif ()

if (WIN32)
  # NOTE: On Windows we have found that we must use Git Bash, not the
  # Bash from the Windows Subsystem for Linux. Hence this is
  # explicitly searching only for Git Bash. See #1302 for more.
  find_program(GIT git)
  get_filename_component(GIT_DIR ${GIT} DIRECTORY)
  find_program(
    OE_BASH bash PATHS "C:/Program Files/Git/bin" "${GIT_DIR}/../bin"
                       NO_DEFAULT_PATH) # Do not find WSL bash.

  if (NOT OE_BASH)
    message(FATAL_ERROR "Git Bash not found!")
  endif ()
  if (NOT NUGET_PACKAGE_PATH)
    message(
      FATAL_ERROR
        "NUGET_PACKAGE_PATH not defined. Please define NUGET_PACKAGE_PATH as the path to the installed Intel and DCAP Client nuget packages."
    )
  endif ()
else ()
  find_program(OE_BASH bash)
  if (NOT OE_BASH)
    message(FATAL_ERROR "Bash not found!")
  endif ()
endif ()

# See `cmake/enclave_cmake_wrappers.cmake` for wrapper functions.
include(enclave_cmake_wrappers)

# This is always included.
# maybe_build_using_clangw will be a noop if USE_CLANGW is false.
include(maybe_build_using_clangw)

# See `cmake/compiler_settings.cmake` for all compiler settings
include(compiler_settings)

# See `cmake/package_settings.cmake` for all package settings
include(package_settings)

# See `cmake/add_enclave.cmake` for enclave creation logic
include(add_enclave)

# User configurable options.
option(
  HAS_QUOTE_PROVIDER
  "Take a build dependency on SGX DCAP, which requires FLC on target device to run."
  ON)

# TODO: See #756: Fix this because it is incompatible with
# multi-configuration generators
if (uppercase_CMAKE_BUILD_TYPE STREQUAL "DEBUG" AND NOT WIN32)
  # In non-win32 debug build, debug_malloc is on by default
  option(USE_DEBUG_MALLOC
         "Build oeenclave with memory leak detection capability." ON)
else ()
  # In win32 or non-debug builds, debug_malloc is off by default
  option(USE_DEBUG_MALLOC
         "Build oeenclave with memory leak detection capability." OFF)
endif ()

option(ADD_WINDOWS_ENCLAVE_TESTS "Build Windows enclave tests" OFF)

# NOTE: Building OpenEnclave using snmalloc for memory allocation is an experimental option.
# Longer term, there will be a pluggable allocator mechanism to allow users to choose from a
# selection of allocators.
option(
  USE_SNMALLOC
  "[EXPERIMENTAL] Build using snmalloc. If this is not set, dlmalloc is used."
  OFF)
if (NOT USE_SNMALLOC)
  set(USE_DLMALLOC true)
endif ()

option(
  COMPILE_SYSTEM_EDL
  "Build system ecalls and ocalls into OE libraries. If not set, they must be included by application EDL to use."
  ON)

option(BUILD_TESTS "Build OE tests" ON)

# For EEID see https://github.com/openenclave/openenclave/pull/2647
option(
  WITH_EEID
  "[EXPERIMENTAL] Include support for Extended Enclave Initialization Data."
  OFF)

if (WITH_EEID AND WIN32)
  message(FATAL_ERROR "WITH_EEID is not supported on Windows yet.")
elseif (WITH_EEID AND OE_TRUSTZONE)
  message(FATAL_ERROR "WITH_EEID is not supported on ARM yet.")
endif ()

find_program(VALGRIND "valgrind")
if (VALGRIND)
  set(MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --error-exitcode=1")
  # include Dart to generate the site configuration:
  # https://gitlab.kitware.com/cmake/community/wikis/doc/ctest/Generating-Testing-Files#using-cmake
  include(Dart)
  message(STATUS "ExperimentalMemCheck can be used to run tests under valgrind")
else ()
  message(STATUS "Valgrind not found")
endif ()
# Configure testing
enable_testing()
include(add_enclave_test)

# Recurse through subdirectories
add_subdirectory(include)
add_subdirectory(host)

# Tests are not ported to include system edl files in order to use system
# ocalls and ecalls.
if (COMPILE_SYSTEM_EDL)

  if (BUILD_TESTS)
    add_subdirectory(tests)
  endif ()

  if (BUILD_ENCLAVES)
    add_subdirectory(samples)
  endif ()
else ()
  if (BUILD_TESTS AND OE_SGX)
    add_subdirectory(tests/exclude_system_edl)
  endif ()
endif ()

add_subdirectory(tools)

if (BUILD_ENCLAVES)
  add_subdirectory(enclave)
  add_subdirectory(3rdparty)
  add_subdirectory(libc)
  add_subdirectory(libcxx)
  add_subdirectory(syscall)
endif ()

if (OE_SGX)
  add_subdirectory(debugger)
endif ()

if (UNIX)
  add_subdirectory(docs/refman)
  add_subdirectory(pkgconfig)
endif ()

if (WIN32)
  install(FILES ./scripts/clangw ./scripts/llvm-arw
          DESTINATION ${CMAKE_INSTALL_BINDIR}/scripts/)
  install(FILES ./scripts/install-windows-prereqs.ps1
          DESTINATION ${CMAKE_INSTALL_BINDIR}/scripts/)
  install(FILES ./cmake/maybe_build_using_clangw.cmake
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake)
  install(FILES ./cmake/add_dcap_client_target.cmake
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake)
  install(FILES ./cmake/copy_oedebugrt_target.cmake
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake)
endif ()

# Install necessary files for LVI mitigation.
if (LVI_MITIGATION MATCHES ControlFlow)
  if (UNIX)
    install(
      FILES ./scripts/lvi-mitigation/install_lvi_mitigation_bindir
      PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ
                  WORLD_EXECUTE WORLD_READ
      DESTINATION ${CMAKE_INSTALL_BINDIR}/scripts/lvi-mitigation)
    install(
      FILES ./scripts/lvi-mitigation/generate_wrapper
      PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ
                  WORLD_EXECUTE WORLD_READ
      DESTINATION ${CMAKE_INSTALL_BINDIR}/scripts/lvi-mitigation)
    install(
      FILES ./scripts/lvi-mitigation/invoke_compiler
      PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ
                  WORLD_EXECUTE WORLD_READ
      DESTINATION ${CMAKE_INSTALL_BINDIR}/scripts/lvi-mitigation)
    install(FILES ./cmake/configure_lvi_mitigation_build.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake)
  else ()
    # For Windows.
    install(FILES ./scripts/lvi-mitigation/lvi-mitigation.py
            DESTINATION ${CMAKE_INSTALL_BINDIR}/scripts/lvi-mitigation)
  endif ()
  install(FILES ./cmake/apply_lvi_mitigation.cmake
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake)
endif ()

install(FILES LICENSE THIRD_PARTY_NOTICES
        DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/licenses)

# Configure all the CPACK settings. This must be last because
# CPack must be aware of all the component information in order
# for it to create different component based packages.
include(cpack_settings)
