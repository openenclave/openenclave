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
  if (lang STREQUAL "ALL")
    add_compile_options(${flag})
  else()
    add_compile_options($<$<COMPILE_LANGUAGE:${lang}>:${flag}>)
  endif()
endfunction()

function(_add_target_compile_flag lang target flag)
  if (lang STREQUAL "ALL")
    target_compile_options(${target} PRIVATE ${flag})
  else()
    target_compile_options(${target} PRIVATE $<$<COMPILE_LANGUAGE:${lang}>:${flag}>)
  endif()
endfunction()

function(_add_compile_flags_if_supported lang)
  foreach(flag ${ARGN})
    _check_compile_flag_supported(${lang} ${flag} supported)
    if (supported)
      _add_compile_flag(${lang} ${flag})
    endif()
  endforeach()
endfunction()

# Note that two underscores are required to work around a bug in CMake
# where it otherwise ends up in an infinite recursive loop calling the wrong function.
function(__add_target_compile_flags_if_supported lang target)
  foreach(flag ${ARGN})
    _check_compile_flag_supported(${lang} ${flag} supported)
    if (supported)
      _add_target_compile_flag(${lang} ${target} ${flag})
    endif()
  endforeach()
endfunction()

function(add_c_compile_flags_if_supported)
  _add_compile_flags_if_supported(C ${ARGN})
endfunction()

function(add_cxx_compile_flags_if_supported)
  _add_compile_flags_if_supported(CXX ${ARGN})
endfunction()

function(add_compile_flags_if_supported)
  _add_compile_flags_if_supported(ALL ${ARGN})
endfunction()

function(add_target_c_compile_flags_if_supported)
  __add_target_compile_flags_if_supported(C ${ARGN})
endfunction()

function(add_target_cxx_compile_flags_if_supported)
  __add_target_compile_flags_if_supported(CXX ${ARGN})
endfunction()

function(add_target_compile_flags_if_supported)
  __add_target_compile_flags_if_supported(ALL ${ARGN})
endfunction()