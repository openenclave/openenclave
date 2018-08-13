# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# Mangle the name of a compiler flag into a valid CMake identifier.
# Ex: --std=c++11 -> STD_EQ_CXX11
function(_mangle_name str output)
  string(STRIP "${str}" strippedStr)
  string(REGEX REPLACE "^/" "" strippedStr "${strippedStr}")
  string(REGEX REPLACE "^-+" "" strippedStr "${strippedStr}")
  string(REGEX REPLACE "-+$" "" strippedStr "${strippedStr}")
  string(REPLACE " " "" strippedStr "${strippedStr}") # for flag pairs like -mllvm -...
  string(REPLACE "-" "_" strippedStr "${strippedStr}")
  string(REPLACE "=" "_EQ_" strippedStr "${strippedStr}")
  string(REPLACE "+" "X" strippedStr "${strippedStr}")
  string(TOUPPER "${strippedStr}" upperStr)
  set(${output} "${upperStr}" PARENT_SCOPE)
endfunction()

function(_get_proxy_flag_if_needed flag proxy_flag)
  # GCC does not output a warning for unsupported -Wno-* (except -Wno-error=*)
  # flags, but it does when another warning occurs. This then leads to an error
  # when using -Werror as well. Clang always outputs warnings and allows
  # to control this behaviour with its -Wno-unknown-warning-option flag.
  # CMake's check_*_compiler_flag macros lead to a false positive for GCC.
  # To work around this, for GCC, we simply check the non-negated form to detect
  # supported flags reliably.
  if (CMAKE_C_COMPILER_ID MATCHES "GNU" AND flag MATCHES "-Wno-" AND NOT flag MATCHES "-Wno-error=")
    string(REPLACE "-Wno-" "-W" positive_flag ${flag})
    set(${proxy_flag} ${positive_flag} PARENT_SCOPE)
  else()
    set(${proxy_flag} ${flag} PARENT_SCOPE)
  endif()
endfunction()

function(_check_c_compile_flag_supported flag supported)
  _mangle_name("${flag}" flagname)
  if (NOT DEFINED SUPPORTS_C_${flagname}_FLAG)
    message(STATUS "Checking if C compiler supports ${flag}")
  endif()
  _get_proxy_flag_if_needed(${flag} flag)
  check_c_compiler_flag("${flag}" "SUPPORTS_C_${flagname}_FLAG")
  set(${supported} ${SUPPORTS_C_${flagname}_FLAG} PARENT_SCOPE)
endfunction()

function(_check_cxx_compile_flag_supported flag supported)
  _mangle_name("${flag}" flagname)
  if (NOT DEFINED SUPPORTS_CXX_${flagname}_FLAG)
    message(STATUS "Checking if C++ compiler supports ${flag}")
  endif()
  _get_proxy_flag_if_needed(${flag} flag)
  check_cxx_compiler_flag("${flag}" "SUPPORTS_CXX_${flagname}_FLAG")
  set(${supported} ${SUPPORTS_CXX_${flagname}_FLAG} PARENT_SCOPE)
endfunction()

function(_check_c_and_cxx_compile_flag_supported flag supported)
  _check_c_compile_flag_supported(${flag} supported_c)
  _check_cxx_compile_flag_supported(${flag} supported_cxx)
  if (supported_c AND supported_cxx)
    set(${supported} TRUE PARENT_SCOPE)
  elseif((supported_c AND NOT supported_cxx) OR (NOT supported_c AND supported_cxx))
    message(FATAL_ERROR "Programming error: ${flag} not supported by both C and C++ compiler,\
      use language-specific add_*_compile_flags_if_supported functions")
  else()
    set(${supported} FALSE PARENT_SCOPE)
  endif()
endfunction()

function(_check_compile_flag_supported lang flag supported)
  if (lang STREQUAL "C")
    _check_c_compile_flag_supported(${flag} _supported)
  elseif (lang STREQUAL "CXX")
    _check_cxx_compile_flag_supported(${flag} _supported)
  elseif (lang STREQUAL "ALL")
    _check_c_and_cxx_compile_flag_supported(${flag} _supported)
  else()
    message(FATAL_ERROR "Unsupported language: ${lang}")
  endif()
  set(${supported} ${_supported} PARENT_SCOPE)
endfunction()

function(_add_compile_flag lang flag)
  separate_arguments(flag) # for flag pairs like -mllvm -...
  foreach (flag_ IN LISTS flag)
    if (lang STREQUAL "ALL")
      add_compile_options($<$<COMPILE_LANGUAGE:C>:${flag_}> $<$<COMPILE_LANGUAGE:CXX>:${flag_}>)
    else()
      add_compile_options($<$<COMPILE_LANGUAGE:${lang}>:${flag_}>)
    endif()
  endforeach()
endfunction()

function(_add_target_compile_flag lang target scope flag)
  separate_arguments(flag)
  foreach (flag_ IN LISTS flag)
    if (lang STREQUAL "ALL")
      target_compile_options(${target} ${scope}
        $<$<COMPILE_LANGUAGE:C>:${flag_}> $<$<COMPILE_LANGUAGE:CXX>:${flag_}>)
    else()
      target_compile_options(${target} ${scope} $<$<COMPILE_LANGUAGE:${lang}>:${flag_}>)
    endif()
  endforeach()
endfunction()

function(_add_compile_flag_if_supported lang flag supported)
  _check_compile_flag_supported(${lang} ${flag} _supported)
  if (_supported)
    _add_compile_flag(${lang} ${flag})
  endif()
  set(${supported} ${_supported} PARENT_SCOPE)
endfunction()

function(_add_compile_flags_if_supported lang)
  foreach(flag ${ARGN})
    _add_compile_flag_if_supported(${lang} ${flag} _)
  endforeach()
endfunction()

# Note that two underscores are required to work around a bug in CMake
# where it otherwise ends up in an infinite recursive loop calling the wrong function.
function(__add_target_compile_flag_if_supported lang target scope flag supported)
  _check_compile_flag_supported(${lang} ${flag} _supported)
  if (_supported)
    _add_target_compile_flag(${lang} ${target} ${scope} ${flag})
  endif()
  set(${supported} ${_supported} PARENT_SCOPE)
endfunction()

function(__add_target_compile_flags_if_supported lang target scope)
  foreach(flag ${ARGN})
    __add_target_compile_flag_if_supported(${lang} ${target} ${scope} ${flag} _)
  endforeach()
endfunction()

# Check whether the C compiler supports a given flag and, if supported,
# add the flag to the compilation of C source files.
#
# Usage:
#
#	  add_c_compile_flag_if_supported(<flag> <supportedvar>)
#
# Arguments:
# 
#  <flag> - Flag to be added.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

# Macros are used here to easily fill the 'supported' output variable.
macro(add_c_compile_flag_if_supported)
  _add_compile_flag_if_supported(C ${ARGN})
endmacro()

# Check whether the C++ compiler supports a given flag and, if supported,
# add the flag to the compilation of C++ source files.
#
# Usage:
#
#	  add_cxx_compile_flag_if_supported(<flag> <supportedvar>)
#
# Arguments:
# 
#  <flag> - Flag to be added.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

macro(add_cxx_compile_flag_if_supported)
  _add_compile_flag_if_supported(CXX ${ARGN})
endmacro()

# Check whether both the C and C++ compilers support a given flag and, if supported,
# add the flag to the compilation of C and C++ source files.
#
# Usage:
#
#	  add_compile_flag_if_supported(<flag> <supportedvar>)
#
# Arguments:
# 
#  <flag> - Flag to be added.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

macro(add_compile_flag_if_supported)
  _add_compile_flag_if_supported(ALL ${ARGN})
endmacro()

# Check whether the C compiler supports a given flag and, if supported,
# add the flag to the compilation of C source files for the given target.
#
# Usage:
#
#	  add_target_c_compile_flag_if_supported(
#     <target> <scope> <flag> <supportedvar>)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flag: INTERFACE|PUBLIC|PRIVATE.
#  <flag> - Flag to be added.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

macro(add_target_c_compile_flag_if_supported)
  __add_target_compile_flag_if_supported(C ${ARGN})
endmacro()

# Check whether the C++ compiler supports a given flag and, if supported,
# add the flag to the compilation of C++ source files for the given target.
#
# Usage:
#
#	  add_target_cxx_compile_flag_if_supported(
#     <target> <scope> <flag> <supportedvar>)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flag: INTERFACE|PUBLIC|PRIVATE.
#  <flag> - Flag to be added.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

macro(add_target_cxx_compile_flag_if_supported)
  __add_target_compile_flag_if_supported(CXX ${ARGN})
endmacro()

# Check whether both the C and C++ compilers support a given flag and, if supported,
# add the flag to the compilation of C and C++ source files for the given target.
#
# Usage:
#
#	  add_target_compile_flag_if_supported(
#     <target> <scope> <flag> <supportedvar>)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flag: INTERFACE|PUBLIC|PRIVATE.
#  <flag> - Flag to be added.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

macro(add_target_compile_flag_if_supported)
  __add_target_compile_flag_if_supported(ALL ${ARGN})
endmacro()

# Check for each given flag whether the C compiler supports it and, if supported,
# add the flag to the compilation of C source files.
#
# Usage:
#
#	  add_c_compile_flags_if_supported(<flag1> [<flag2>] ...)
#
# Arguments:
# 
#  <flagn> - Flags to be added.

function(add_c_compile_flags_if_supported)
  _add_compile_flags_if_supported(C ${ARGN})
endfunction()

# Check for each given flag whether the C++ compiler supports it and, if supported,
# add the flag to the compilation of C++ source files.
#
# Usage:
#
#	  add_cxx_compile_flags_if_supported(<flag1> [<flag2>] ...)
#
# Arguments:
# 
#  <flagn> - Flags to be added.

function(add_cxx_compile_flags_if_supported)
  _add_compile_flags_if_supported(CXX ${ARGN})
endfunction()

# Check for each given flag whether both the C and C++ compilers support it and, if supported,
# add the flag to the compilation of C and C++ source files.
#
# Usage:
#
#	  add_compile_flags_if_supported(<flag1> [<flag2>] ...)
#
# Arguments:
# 
#  <flagn> - Flags to be added.

function(add_compile_flags_if_supported)
  _add_compile_flags_if_supported(ALL ${ARGN})
endfunction()

# Check for each given flag whether the C compiler supports it and, if supported,
# add the flag to the compilation of C source files for the given target.
#
# Usage:
#
#	  add_target_c_compile_flags_if_supported(
#     <target> <scope> <flag1> [<flag2>] ...)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flags: INTERFACE|PUBLIC|PRIVATE.
#  <flagn> - Flags to be added.

function(add_target_c_compile_flags_if_supported)
  __add_target_compile_flags_if_supported(C ${ARGN})
endfunction()

# Check for each given flag whether the C++ compiler supports it and, if supported,
# add the flag to the compilation of C++xx source files for the given target.
#
# Usage:
#
#	  add_target_cxx_compile_flags_if_supported(
#     <target> <scope> <flag1> [<flag2>] ...)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flags: INTERFACE|PUBLIC|PRIVATE.
#  <flagn> - Flags to be added.

function(add_target_cxx_compile_flags_if_supported)
  __add_target_compile_flags_if_supported(CXX ${ARGN})
endfunction()

# Check for each given flag whether both the C and C++ compilers support it and, if supported,
# add the flag to the compilation of C and C++ source files for the given target.
#
# Usage:
#
#	  add_target_compile_flags_if_supported(
#     <target> <scope> <flag1> [<flag2>] ...)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flags: INTERFACE|PUBLIC|PRIVATE.
#  <flagn> - Flags to be added.

function(add_target_compile_flags_if_supported)
  __add_target_compile_flags_if_supported(ALL ${ARGN})
endfunction()
