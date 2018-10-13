# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Check Clang version.
if (CMAKE_C_COMPILER_ID MATCHES Clang)
  if (CMAKE_C_COMPILER_VERSION VERSION_LESS 7 OR
      CMAKE_C_COMPILER_VERSION VERSION_GREATER 7.99)
    message(WARNING "Open Enclave officially supports Clang 7 only, "
      "but your Clang version (${CMAKE_C_COMPILER_VERSION}) "
      "is older or newer than that. Build problems may occur.")
  endif ()
endif ()

include(add_compile_flags_if_supported)

if (NOT CMAKE_C_COMPILER_ID STREQUAL CMAKE_CXX_COMPILER_ID)
  message(FATAL_ERROR "Your C and C++ compilers have different vendors: "
    "${CMAKE_C_COMPILER_ID} != ${CMAKE_CXX_COMPILER_ID}")
endif ()

# Set default build type and sanitize.
# TODO: See #756: Fix this since debug is the default.
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif ()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug;Release;RelWithDebInfo")

string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_SUFFIX)
if (NOT DEFINED CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_SUFFIX})
  message(FATAL_ERROR "Unknown CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE_SUFFIX}")
endif ()

# TODO: See #758: Fix this to check 64-bit correctly with
# `CMAKE_SIZEOF_VOID_P EQUAL 8` (on all platforms).
if (DEFINED CMAKE_VS_PLATFORM_NAME)
  if (NOT ${CMAKE_VS_PLATFORM_NAME} STREQUAL "x64")
    message(FATAL_ERROR "With Visual Studio, configure Win64 build generator explicitly.")
  endif ()
endif ()

# Use ccache if available.
# TODO: See #759: Replace this with `CMAKE_<LANG>_COMPILER_LAUNCHER`.
find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
  message("Using ccache")
else ()
  message("ccache not found")
endif (CCACHE_FOUND)

# Apply Spectre mitigations if available.
set(SPECTRE_1_LLVM_MITIGATION_FLAG "-mllvm -x86-speculative-load-hardening")
add_compile_flag_if_supported("C;CXX" "${SPECTRE_1_LLVM_MITIGATION_FLAG}" SPECTRE_1_LLVM_MITIGATION_FLAG_SUPPORTED)

if (SPECTRE_1_LLVM_MITIGATION_FLAG_SUPPORTED)
  message("C/C++ compiler is Clang 7.0+, applying Spectre 1 mitigations")
else ()
  set(SPECTRE_1_LLVM_MITIGATION_FLAG "")
  message("C/C++ compiler is not Clang 7.0+, NOT applying Spectre 1 mitigations")
endif ()

# Allows reuse in cases where ExternalProject is used and global compile flags wouldn't propagate.
set(SPECTRE_MITIGATION_FLAGS "${SPECTRE_1_LLVM_MITIGATION_FLAG}")

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  # Disable this particular warning because `-isystem` is being to
  # sent to clang when assembling, and is at that point unrecognized.
  # TODO: See #760: Fix this when errors are better propagated.
  add_compile_options(-Wno-error=unused-command-line-argument)
endif ()

if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
  # Enables all the warnings about constructions that some users consider questionable,
  # and that are easy to avoid. Treat at warnings-as-errors, which forces developers
  # to fix warnings as they arise, so they don't accumulate "to be fixed later".
  add_compile_options(-Wall -Werror)

  add_compile_options(-fno-strict-aliasing)

  add_compile_flags_if_supported(C -Wjump-misses-init)

  # Enables XSAVE intrinsics.
  add_compile_options(-mxsave)

  # Obtain default compiler include dir to gain access to intrinsics
  execute_process(
    COMMAND /bin/bash ${PROJECT_SOURCE_DIR}/cmake/get_c_compiler_dir.sh ${CMAKE_C_COMPILER}
    OUTPUT_VARIABLE OE_C_COMPILER_INCDIR
    ERROR_VARIABLE OE_ERR)

  if (NOT OE_ERR STREQUAL "")
    message(FATAL_ERROR ${OE_ERR})
  endif ()

  # We should only need this for in-enclave code but it's easier
  # and conservative to specify everywhere
  add_compile_options(-fno-builtin-malloc -fno-builtin-calloc)
elseif (MSVC)
  # MSVC options go here
endif ()

# Use ML64 as assembler on Windows
if (WIN32)
  set(CMAKE_ASM_MASM_COMPILER "ml64")
endif ()
