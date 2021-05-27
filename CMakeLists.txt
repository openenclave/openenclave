# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
#
# Top-level CMake file for the Open Enclave SDK
#
# Please read The Ultimate Guide to CMake:
# https://rix0r.nl/blog/2015/08/13/cmake-guide/
cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Include utilities such as `check_submodule_not_empty`.
include(utilities)

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

if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
  set(CMAKE_BUILD_TYPE "Debug")
endif ()

# Validate CMAKE_BUILD_TYPE
string(TOUPPER "${CMAKE_BUILD_TYPE}" uppercase_CMAKE_BUILD_TYPE)
list(APPEND uppercase_build_type "DEBUG" "RELEASE" "RELWITHDEBINFO")
if (NOT uppercase_CMAKE_BUILD_TYPE IN_LIST uppercase_build_type)
  message(FATAL_ERROR "UNKNOWN CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif ()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

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

option(BUILD_OPENSSL "[EXPERIMENTAL] Build OpenSSL libraries." OFF)

if (BUILD_OPENSSL AND OE_TRUSTZONE)
  message(FATAL_ERROR "BUILD_OPENSSL is not supported on ARM yet.")
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

  # Looking for Perl and Dos2unix if BUILD_OPENSSL is ON.
  if (BUILD_OPENSSL)
    # OpenSSL relies on Perl to generate files (e.g., headers, assembly files, and test cases).
    find_program(OE_PERL perl PATHS "C:/Program Files/Git/bin"
                                    "${GIT_DIR}/../usr/bin" NO_DEFAULT_PATH)
    if (NOT OE_PERL)
      message(FATAL_ERROR "Perl not found!")
    endif ()

    # Dos2unix utility is used to convert CRLF to LF, which is required by some
    # OpenSSL tests.
    find_program(
      OE_DOS2UNIX dos2unix PATHS "C:/Program Files/Git/bin"
                                 "${GIT_DIR}/../usr/bin" NO_DEFAULT_PATH)
    if (NOT OE_DOS2UNIX)
      message(FATAL_ERROR "Dos2unix not found!")
    endif ()
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

  # Looking for Perl if BUILD_OPENSSL is ON.
  if (BUILD_OPENSSL)
    # OpenSSL relies on Perl to generate files (e.g., headers, assembly files, and test cases).
    find_program(OE_PERL perl)
    if (NOT OE_PERL)
      message(FATAL_ERROR "Perl not found!")
    endif ()
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

# TODO: See #756: Fix this because it is incompatible with
# multi-configuration generators
if (uppercase_CMAKE_BUILD_TYPE STREQUAL "DEBUG")
  # In debug builds, enclaves are linked with liboedebugmalloc.a by default.
  option(USE_DEBUG_MALLOC
         "Build enclaves with memory leak detection capability." ON)
endif ()

option(ADD_WINDOWS_ENCLAVE_TESTS "Build Windows enclave tests" OFF)

# snmalloc uses C++17 `if constexpr` which is available in GCC 7.1 and above.
# Ubuntu 16.04's GCC is 5.4.0.
# Versions of clang which we care about support the construct.
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" AND CMAKE_CXX_COMPILER_VERSION
                                            VERSION_LESS "7.1")
  set(COMPILER_SUPPORTS_SNMALLOC off)
else ()
  set(COMPILER_SUPPORTS_SNMALLOC on)
endif ()

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

# Option to build and expose the libgcov such that enclave applications can use.
# Note that this option is only effective when CODE_COVERAGE is not set.
option(BUILD_LIBGCOV "Build the code coverage library" OFF)

option(CODE_COVERAGE "Enable code coverage testing" OFF)
if (CODE_COVERAGE)
  if (WIN32)
    message(
      FATAL_ERROR
        "The CODE_COVERAGE option currently is not supported on Windows.")
  endif ()
  if (USE_DEBUG_MALLOC)
    message(
      FATAL_ERROR
        "The CODE_COVERAGE option currently is not supported when the USE_DEBUG_MALLOC option is ON."
    )
  endif ()
  message("-- CODE_COVERAGE set - enable code coverage tests")

  if (CMAKE_C_COMPILER_ID MATCHES GNU)
    message(FATAL_ERROR "Code coverage is currently only supported by clang.")
  else ()
    if (CMAKE_C_COMPILER_VERSION VERSION_LESS 7 OR CMAKE_C_COMPILER_VERSION
                                                   VERSION_GREATER 7.99)
      message(
        WARNING "Code coverage may not work with clang versions other than 7.")
    endif ()
  endif ()

  find_program(LCOV "lcov")
  if (LCOV)
    message("-- LCOV is found")
  else ()
    message(FATAL_ERROR "LCOV is not found.")
  endif ()

  add_custom_target(
    code_coverage
    COMMAND mkdir -p coverage
    COMMAND lcov -c -i -d ${CMAKE_BINARY_DIR} --gcov-tool
            ${OE_SCRIPTSDIR}/code-coverage/llvm-gcov -o coverage/base.info
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

  set(FILTERED_LIST
      "'${PROJECT_SOURCE_DIR}/tests/*'" "'${PROJECT_SOURCE_DIR}/3rdparty/*'"
      "'${CMAKE_BINARY_DIR}/tests/*'" "'${CMAKE_BINARY_DIR}/3rdparty/*'")

  add_custom_command(
    TARGET code_coverage
    COMMAND
      lcov -d ${CMAKE_BINARY_DIR} --gcov-tool
      ${OE_SCRIPTSDIR}/code-coverage/llvm-gcov -c -o cov.info --rc
      lcov_branch_coverage=1
    COMMAND lcov -a base.info -a cov.info -o cov_total.info --rc
            lcov_branch_coverage=1
    COMMAND lcov --remove cov_total.info ${FILTERED_LIST} -o cov_filtered.info
            --rc lcov_branch_coverage=1
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/coverage)

  add_custom_command(
    TARGET code_coverage
    DEPENDS ${CMAKE_BINARY_DIR}/coverage/cov_filtered.info
    COMMAND
      ${OE_SCRIPTSDIR}/code-coverage/lcov_cobertura
      ${CMAKE_BINARY_DIR}/coverage/cov_filtered.info -o
      ${CMAKE_BINARY_DIR}/coverage/coverage.xml
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})

  add_custom_target(
    code_coverage_clean
    COMMAND find ${CMAKE_BINARY_DIR} -type f -name '*.gcda' -delete
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
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

if (BUILD_TESTS AND (NOT COMPONENT MATCHES OEHOSTVERIFY))
  add_subdirectory(tests)
endif ()

# Skip samples when enabling the code coverage test.
# Otherwise, all the samples need to explicitly link against the libgcov library.
if (NOT CODE_COVERAGE)
  add_subdirectory(samples)
endif ()

if (NOT COMPONENT MATCHES OEHOSTVERFIY)
  add_subdirectory(tools)
endif ()

if (BUILD_ENCLAVES AND (NOT COMPONENT MATCHES OEHOSTVERIFY))
  add_subdirectory(enclave)
  add_subdirectory(3rdparty)
  add_subdirectory(libc)
  add_subdirectory(libcxx)
  add_subdirectory(syscall)
endif ()

if (OE_SGX AND (NOT COMPONENT MATCHES OEHOSTVERIFY))
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
