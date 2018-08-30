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
  if (CMAKE_C_COMPILER_ID MATCHES "GNU" AND 
      flag MATCHES "-Wno-" AND NOT flag MATCHES "-Wno-error=")
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

function(_add_compile_flag lang flag)
  separate_arguments(flag) # for flag pairs like -mllvm -...
  foreach (_flag IN LISTS flag)
    foreach (_lang IN LISTS lang)
      add_compile_options($<$<COMPILE_LANGUAGE:${_lang}>:${_flag}>)
    endforeach()
  endforeach()
endfunction()

function(_add_target_compile_flag target scope lang flag)
  separate_arguments(flag)
  foreach (_flag IN LISTS flag)
    foreach (_lang IN LISTS lang)
      target_compile_options(${target} ${scope}
        $<$<COMPILE_LANGUAGE:${_lang}>:${_flag}>)
    endforeach()
  endforeach()
endfunction()

# Check whether the compiler(s) for the given language(s) support a given flag.
#
# Usage:
#
#	  check_compile_flag_supported(
#       <lang> <flag> <supportedvar>)
#
# Arguments:
# 
#  <lang> - Languages for which to check the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <flag> - Flag to check.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

function(check_compile_flag_supported lang flag supported)
  set(result "null")
  foreach (_lang IN LISTS lang)
    if (_lang STREQUAL "C")
      _check_c_compile_flag_supported(${flag} _supported)
    elseif (_lang STREQUAL "CXX")
      _check_cxx_compile_flag_supported(${flag} _supported)
    else()
      message(FATAL_ERROR "Unsupported language: ${_lang}")
    endif()
    if (result STREQUAL "null")
      set(result ${_supported})
    else()
      if ((result AND NOT _supported) OR (NOT result AND _supported))
        message(FATAL_ERROR "Programming error: ${flag} not supported by all \
          compilers for languages ${lang}. Split flags into separate \
          function calls.")
      endif()
    endif()
  endforeach()
  set(${supported} ${result} PARENT_SCOPE)
endfunction()

# Add the flags to the compilation of source files.
#
# Usage:
#
#	  add_compile_flags(
#       <lang> <flag1> [<flag2>] ...)
#
# Arguments:
#
#  <lang> - Languages for which to add the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <flagn> - Flags to be added.

function(add_compile_flags lang)
  foreach(flag ${ARGN})
    _add_compile_flag("${lang}" ${flag} _)
  endforeach()
endfunction()

# Add the flags to the compilation of source files for the given target.
#
# Usage:
#
#	  add_target_compile_flags(
#       <target> <scope> <lang> <flag1> [<flag2>] ...)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flags: INTERFACE|PUBLIC|PRIVATE.
#  <lang> - Languages for which to add the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <flagn> - Flags to be added.

function(add_target_compile_flags target scope lang)
  foreach(flag ${ARGN})
    _add_target_compile_flag(${target} ${scope} "${lang}" ${flag} _)
  endforeach()
endfunction()

# Check whether the compiler(s) for the given language(s) support a given flag
# and, if supported, add the flag to the compilation of source files.
#
# Usage:
#
#	  add_compile_flag_if_supported(
#       <lang> <flag> <supportedvar>)
#
# Arguments:
# 
#  <lang> - Languages for which to add the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <flag> - Flag to be added.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

function(add_compile_flag_if_supported lang flag supported)
  check_compile_flag_supported("${lang}" ${flag} _supported)
  if (_supported)
    _add_compile_flag("${lang}" ${flag})
  endif()
  set(${supported} ${_supported} PARENT_SCOPE)
endfunction()

# Check whether the compiler(s) for the given language(s) support a given flag
# and, if supported, add the flag to the compilation of source files for
# the given target.
#
# Usage:
#
#	  add_target_compile_flag_if_supported(
#       <target> <scope> <lang> <flag> <supportedvar>)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flag: INTERFACE|PUBLIC|PRIVATE.
#  <lang> - Languages for which to add the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <flag> - Flag to be added.
#  <supportedvar> - Name of the boolean result variable indicating compiler support.

function(add_target_compile_flag_if_supported target scope lang flag supported)
  check_compile_flag_supported("${lang}" ${flag} _supported)
  if (_supported)
    _add_target_compile_flag(${target} ${scope} "${lang}" ${flag})
  endif()
  set(${supported} ${_supported} PARENT_SCOPE)
endfunction()

# Check for each given flag whether the compiler(s) for the given language(s)
# support it and, if supported, add the flag to the compilation of source files.
#
# Usage:
#
#	  add_compile_flags_if_supported(
#       <lang> <flag1> [<flag2>] ...)
#
# Arguments:
#
#  <lang> - Languages for which to add the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <flagn> - Flags to be added.

function(add_compile_flags_if_supported lang)
  foreach(flag ${ARGN})
    add_compile_flag_if_supported("${lang}" ${flag} _)
  endforeach()
endfunction()

# Check for each given flag whether the compiler(s) for the given language(s)
# support it and, if supported, add the flag to the compilation of source files
# for the given target.
#
# Usage:
#
#	  add_target_compile_flags_if_supported(
#       <target> <scope> <lang> <flag1> [<flag2>] ...)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flags: INTERFACE|PUBLIC|PRIVATE.
#  <lang> - Languages for which to add the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <flagn> - Flags to be added.

function(add_target_compile_flags_if_supported target scope lang)
  foreach(flag ${ARGN})
    add_target_compile_flag_if_supported(${target} ${scope} "${lang}" ${flag} _)
  endforeach()
endfunction()
