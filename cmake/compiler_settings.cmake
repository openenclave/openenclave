# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Check Clang version.
if (CMAKE_C_COMPILER_ID MATCHES Clang)
  if (CMAKE_C_COMPILER_VERSION VERSION_LESS 7 OR CMAKE_C_COMPILER_VERSION
                                                 VERSION_GREATER 7.99)
    message(WARNING "Open Enclave officially supports Clang 7 only, "
                    "but your Clang version (${CMAKE_C_COMPILER_VERSION}) "
                    "is older or newer than that. Build problems may occur.")
  endif ()
endif ()

if (NOT CMAKE_C_COMPILER_ID STREQUAL CMAKE_CXX_COMPILER_ID)
  message(FATAL_ERROR "Your C and C++ compilers have different vendors: "
                      "${CMAKE_C_COMPILER_ID} != ${CMAKE_CXX_COMPILER_ID}")
endif ()

set(CMAKE_C_STANDARD 11)

# Set the default standard to C++14 for all targets.
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Do not use, for example, `-std=gnu++14`.
set(CMAKE_CXX_EXTENSIONS OFF)

# Set default build type and sanitize.
# TODO: See #756: Fix this since debug is the default.
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Debug"
      CACHE STRING "Build type" FORCE)
endif ()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                                             "Debug;Release;RelWithDebInfo")

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
check_c_compiler_flag("${SPECTRE_MITIGATION_FLAGS}"
                      SPECTRE_MITIGATION_C_FLAGS_SUPPORTED)
check_cxx_compiler_flag("${SPECTRE_MITIGATION_FLAGS}"
                        SPECTRE_MITIGATION_CXX_FLAGS_SUPPORTED)
if (SPECTRE_MITIGATION_C_FLAGS_SUPPORTED
    AND SPECTRE_MITIGATION_CXX_FLAGS_SUPPORTED)
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

if (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
  # Enforce -O0 in debug mode.
  string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_UPPER)
  if (CMAKE_BUILD_TYPE_UPPER STREQUAL "DEBUG")
    # For gcc the -g option alredy includes -O0.
    # Here we just apply -O0 for Clang.
    if (CMAKE_CXX_COMPILER_ID MATCHES Clang)
      set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
      set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
    endif ()
  endif ()
  # Enables all the warnings about constructions that some users consider questionable,
  # and that are easy to avoid. Treat at warnings-as-errors, which forces developers
  # to fix warnings as they arise, so they don't accumulate "to be fixed later".
  add_compile_options(-Wall -Werror -Wpointer-arith -Wconversion -Wextra
                      -Wno-missing-field-initializers)
  add_compile_options(-fno-strict-aliasing)

  # Allow checks which always evaluate to true or false due to type limits.
  # This is required as some macros operate on types of varying sizes.
  add_compile_options(-Wno-type-limits)

  # Enables XSAVE intrinsics
  if (OE_SGX)
    add_compile_options(-mxsave)
  endif ()
elseif (MSVC)
  # MSVC options go here
  if (MSVC_VERSION VERSION_LESS 1910)
    message(FATAL_ERROR "Only Visual Studio 2017 and above supported!")
  endif ()

  # Explicitly set C/CXX flags rather than using the defaults. This uses the defaults
  # but removes /W3 from CMAKE_C(XX)_FLAGS. Using W3 and W1 together adds many warnings
  # that W3 is being overwritten by W1. W3 as a default flag is removed in cmake 3.15,
  # so this behavior can be removed if/when cmake_minimum_required is raised to 3.15.
  # ======= Default compiler flags for cmake version 3.12 can be found here: =======
  # https://github.com/Kitware/CMake/blob/v3.12.0/Modules/Platform/Windows-MSVC.cmake
  set(CMAKE_C_FLAGS "/DWIN32 /D_WINDOWS")
  set(CMAKE_C_FLAGS_DEBUG "/MDd /Zi /Ob0 /Od /RTC1")
  set(CMAKE_C_FLAGS_RELEASE "/MD /O2 /Ob2 /DNDEBUG")

  set(CMAKE_CXX_FLAGS "/DWIN32 /D_WINDOWS /GR /EHsc")
  set(CMAKE_CXX_FLAGS_DEBUG "/DWIN32 /D_WINDOWS /MDd /Zi /Ob0 /Od /RTC1")
  set(CMAKE_CXX_FLAGS_RELEASE "/MD /O2 /Ob2 /DNDEBUG")

  # Can't use add_compile_options because it adds for all file types and ml64
  # doesn't recognize /wd flags
  # Turns off warnings for:
  # * Unicode character cannot be represented by current code page
  # * Flexible array members. These are standard in C99 so we will allow them.
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4566 /wd4200")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4566 /wd4200")

  # Add Flags we want to use for both C and CXX
  add_compile_options(/WX)
  add_compile_options(/W3)

  # Ignore compiler warnings:
  # * unicode character not supported

  if (CMAKE_MSVC_PARALLEL_ENABLE)
    add_compile_options(/MP)
    message(STATUS "Using parallel compiling (/MP)")
  endif ()
endif ()

# Use ML64 as assembler on Windows
if (WIN32)
  set(CMAKE_ASM_MASM_COMPILER "ml64")
endif ()
