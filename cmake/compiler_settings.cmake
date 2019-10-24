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

if (NOT CMAKE_C_COMPILER_ID STREQUAL CMAKE_CXX_COMPILER_ID)
  message(FATAL_ERROR "Your C and C++ compilers have different vendors: "
    "${CMAKE_C_COMPILER_ID} != ${CMAKE_CXX_COMPILER_ID}")
endif ()

# Set the default standard to C++14 for all targets.
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Do not use, for example, `-std=gnu++14`.
set(CMAKE_CXX_EXTENSIONS OFF)

# Set default build type and sanitize.
# TODO: See #756: Fix this since debug is the default.
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif ()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug;Release;RelWithDebInfo")

string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_SUFFIX)
if (NOT DEFINED CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_SUFFIX})
  message(FATAL_ERROR "Unknown CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif ()

# TODO: When ARM support is added, we will need to exclude the check
# as it will be 64-bit.
if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  if (MSVC)
    message(WARNING "Use '-T host=x64' to set the toolchain to 64-bit!")
  endif ()
  message(FATAL_ERROR "Only 64-bit builds are supported!")
endif ()

# Setup ccache
include(ccache)

# Check for compiler flags
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# Apply Spectre mitigations if available.
set(SPECTRE_MITIGATION_FLAGS -mllvm -x86-speculative-load-hardening)
check_c_compiler_flag("${SPECTRE_MITIGATION_FLAGS}" SPECTRE_MITIGATION_C_FLAGS_SUPPORTED)
check_cxx_compiler_flag("${SPECTRE_MITIGATION_FLAGS}" SPECTRE_MITIGATION_CXX_FLAGS_SUPPORTED)
if (SPECTRE_MITIGATION_C_FLAGS_SUPPORTED AND SPECTRE_MITIGATION_CXX_FLAGS_SUPPORTED)
  message(STATUS "Spectre 1 mitigations supported")
  # We set this variable to indicate the flags are supported. It is
  # empty otherwise.
  set(OE_SPECTRE_MITIGATION_FLAGS ${SPECTRE_MITIGATION_FLAGS})
  # TODO: We really should specify this only on the `oecore` target;
  # however, the third-party mbed TLS build needs it set to, so we
  # have to keep this here for now.
  add_compile_options(${OE_SPECTRE_MITIGATION_FLAGS})
else ()
  message(WARNING "Spectre 1 mitigations NOT supported")
endif ()

# Apply Control Flow Guard if available.
set(CONTROL_FLOW_GUARD_FLAGS /guard:cf)
set(CONTROL_FLOW_GUARD_SHARED_LINKER_FLAGS /guard:cf /DYNAMICBASE)
check_c_compiler_flag("${CONTROL_FLOW_GUARD_FLAGS}" CONTROL_FLOW_GUARD_FLAGS_C_SUPPORTED)
check_cxx_compiler_flag("${CONTROL_FLOW_GUARD_FLAGS}"  CONTROL_FLOW_GUARD_FLAGS_CXX_FLAGS_SUPPORTED)
if (CONTROL_FLOW_GUARD_FLAGS_C_SUPPORTED AND CONTROL_FLOW_GUARD_FLAGS_CXX_FLAGS_SUPPORTED)
  message(STATUS "Control Flow GUARD Supported")
  # We set this variable to indicate the flags are supported. It is
  # empty otherwise.
  set(CONTROL_FLOW_GUARD_FLAGS ${CONTROL_FLOW_GUARD_FLAGS})
  set(CMAKE_SHARED_LINKER_FLAGS ${CONTROL_FLOW_GUARD_SHARED_LINKER_FLAGS})
  add_compile_options(${CONTROL_FLOW_GUARD_FLAGS})
else ()
  message(WARNING "Control Flow Guard NOT supported")
endif ()

if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
  # Enables all the warnings about constructions that some users consider questionable,
  # and that are easy to avoid. Treat at warnings-as-errors, which forces developers
  # to fix warnings as they arise, so they don't accumulate "to be fixed later".
  add_compile_options(-Wall -Werror -Wpointer-arith -Wconversion -Wextra -Wno-missing-field-initializers)

  add_compile_options(-fno-strict-aliasing)

  # Enables XSAVE intrinsics
  if (OE_SGX)
      add_compile_options(-mxsave)
  endif()
elseif (MSVC)
  # MSVC options go here
  if (MSVC_VERSION VERSION_LESS 1910)
    message(FATAL_ERROR "Only Visual Studio 2017 and above supported!")
  endif ()
  if (CMAKE_MSVC_PARALLEL_ENABLE)
    add_compile_options(/MP)
    message(STATUS "Using parallel compiling (/MP)")
  endif()

endif ()

# Use ML64 as assembler on Windows
if (WIN32)
  set(CMAKE_ASM_MASM_COMPILER "ml64")
endif ()
