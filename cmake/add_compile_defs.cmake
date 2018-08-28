# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function(_add_compile_def lang def)
  foreach (_lang IN LISTS lang)
    # add_definitions cannot be used here as it lacks support for
    # generator expressions.
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS
      $<$<COMPILE_LANGUAGE:${_lang}>:${def}>)
  endforeach()
endfunction()

function(_add_target_compile_def target scope lang def)
  foreach (_lang IN LISTS lang)
    target_compile_definitions(${target} ${scope}
      $<$<COMPILE_LANGUAGE:${_lang}>:${def}>)
  endforeach()
endfunction()

# Add the preprocessor definitions to the compilation of source files.
#
# Usage:
#
#	  add_compile_defs(
#       <lang> <def1> [<def2>] ...)
#
# Arguments:
#
#  <lang> - Languages for which to add the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <defn> - Definitions to be added without "-D" prefix.

function(add_compile_defs lang)
  foreach(def ${ARGN})
    _add_compile_def("${lang}" ${def})
  endforeach()
endfunction()

# Add the preprocessor definitions to the compilation of source files
# for the given target.
#
# Usage:
#
#	  add_target_compile_defs(
#       <target> <scope> <lang> <def1> [<def1>] ...)
#
# Arguments:
# 
#  <target> - Name of the target.
#  <scope> - Scope of the flags: INTERFACE|PUBLIC|PRIVATE.
#  <lang> - Languages for which to add the flag.
#           If multiple, use semicolon and wrap in quotes.
#  <defn> - Definitions to be added without "-D" prefix.

function(add_target_compile_defs target scope lang)
  foreach(def ${ARGN})
    _add_target_compile_def(${target} ${scope} "${lang}" ${def})
  endforeach()
endfunction()
