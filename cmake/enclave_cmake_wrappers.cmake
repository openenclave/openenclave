# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# This file implements wrappers of cmake functions that are only
# for internal OE build.

# Only include `apply_lvi_mitigation` when enabling LVI mitigation.
if (LVI_MITIGATION MATCHES ControlFlow)
  include(apply_lvi_mitigation)
endif ()

# Wrapper of `add_executable` for adding an enclave with LVI mitigation.
# Note that this macro should be called only from `add_enclave`.
macro (add_lvi_enclave_executable NAME)
  add_executable(${NAME}-lvi-cfg ${ARGN})
  apply_lvi_mitigation(${NAME}-lvi-cfg)
endmacro (add_lvi_enclave_executable)

# Wrapper of `add_dependencies`
macro (add_enclave_dependencies NAME)
  add_dependencies(${NAME} ${ARGN})
  if (TARGET ${NAME}-lvi-cfg)
    add_dependencies(${NAME}-lvi-cfg ${ARGN})
  endif ()
endmacro (add_enclave_dependencies)

# Wrapper of `add_library`
macro (add_enclave_library NAME)
  add_library(${NAME} ${ARGN})
  if (LVI_MITIGATION MATCHES ControlFlow)
    add_library(${NAME}-lvi-cfg ${ARGN})
    # Compiler options are only applicable to non-interface library.
    if (NOT ${ARGV1} MATCHES INTERFACE)
      apply_lvi_mitigation(${NAME}-lvi-cfg)
    endif ()
  endif ()
endmacro (add_enclave_library)

# Wrapper of `target_compile_features`
macro (enclave_compile_definitions NAME)
  target_compile_definitions(${NAME} ${ARGN})
  if (TARGET ${NAME}-lvi-cfg)
    target_compile_definitions(${NAME}-lvi-cfg ${ARGN})
  endif ()
endmacro (enclave_compile_definitions)

# Wrapper of `target_compile_features`
macro (enclave_compile_features NAME)
  target_compile_features(${NAME} ${ARGN})
  if (TARGET ${NAME}-lvi-cfg)
    target_compile_features(${NAME}-lvi-cfg ${ARGN})
  endif ()
endmacro (enclave_compile_features)

# Wrapper of `target_compile_options`
macro (enclave_compile_options NAME)
  target_compile_options(${NAME} ${ARGN})
  if (TARGET ${NAME}-lvi-cfg)
    target_compile_options(${NAME}-lvi-cfg ${ARGN})
  endif ()
endmacro (enclave_compile_options)

# Wrapper of `target_include_directories`
macro (enclave_include_directories NAME)
  target_include_directories(${NAME} ${ARGN})
  if (TARGET ${NAME}-lvi-cfg)
    target_include_directories(${NAME}-lvi-cfg ${ARGN})
  endif ()
endmacro (enclave_include_directories)

# Wrapper of `target_link_libraries`.
function (enclave_link_libraries NAME)
  # Handle each library separately.
  foreach (lib ${ARGN})
    if (lib STREQUAL PUBLIC
        OR lib STREQUAL PRIVATE
        OR lib STREQUAL INTERFACE)
      set(type "${lib}")
      continue()
    endif ()
    target_link_libraries(${NAME} ${type} ${lib})
    if (TARGET ${NAME}-lvi-cfg)
      # Directly apply compiler options and interface or lvi-mitigated libraries.
      if (lib MATCHES "^-"
          OR lib MATCHES "include"
          OR lib MATCHES "-lvi-cfg")
        target_link_libraries(${NAME}-lvi-cfg ${type} ${lib})
        continue()
      endif ()
      # Link to lvi-mitigated libraries.
      target_link_libraries(${NAME}-lvi-cfg ${type} ${lib}-lvi-cfg)
    endif ()
  endforeach (lib)
endfunction (enclave_link_libraries)

# Wrapper of `set_tests_properties`
macro (set_enclave_tests_properties NAME PROPERTIES)
  set_tests_properties(${NAME} PROPERTIES ${ARGN})
  if (TEST ${NAME}-lvi-cfg)
    set_tests_properties(${NAME}-lvi-cfg PROPERTIES ${ARGN})
  endif ()
endmacro (set_enclave_tests_properties)

macro (set_enclave_properties NAME PROPERTIES)
  set_target_properties(${NAME} PROPERTIES ${ARGN})
  if (TARGET ${NAME}-lvi-cfg)
    set_target_properties(${NAME}-lvi-cfg PROPERTIES ${ARGN})
  endif ()
endmacro (set_enclave_properties)

# Wrapper of `set_property`
macro (set_enclave_property TARGET NAME PROPERTY)
  set_property(TARGET ${NAME} PROPERTY ${ARGN})
  if (TARGET ${NAME}-lvi-cfg)
    set_property(TARGET ${NAME}-lvi-cfg PROPERTY ${ARGN})
  endif ()
endmacro (set_enclave_property)

# Wrapper of `install`. Note that this wrapper only supports the subset
# of `install` supported arguments, which is sufficient for current needs.
function (install_enclaves)
  set(options ARCHIVE)
  set(onevalueArgs EXPORT DESTINATION)
  set(multiValueArgs TARGETS)
  cmake_parse_arguments(ENCLAVE "${options}" "${onevalueArgs}"
                        "${multiValueArgs}" ${ARGN})
  foreach (target ${ENCLAVE_TARGETS})
    if (ENCLAVE_ARCHIVE AND ENCLAVE_DESTINATION)
      install(
        TARGETS ${target}
        EXPORT ${ENCLAVE_EXPORT}
        ARCHIVE DESTINATION ${ENCLAVE_DESTINATION})
      if (TARGET ${target}-lvi-cfg)
        install(
          TARGETS ${target}-lvi-cfg
          EXPORT ${ENCLAVE_EXPORT}
          ARCHIVE DESTINATION ${ENCLAVE_DESTINATION})
      endif ()
    else ()
      install(TARGETS ${target} EXPORT ${ENCLAVE_EXPORT})
      if (TARGET ${target}-lvi-cfg)
        install(TARGETS ${target}-lvi-cfg EXPORT ${ENCLAVE_EXPORT})
      endif ()
    endif ()
  endforeach (target)
endfunction (install_enclaves)

function (enclave_enable_code_coverage NAME)
  if (NOT CODE_COVERAGE)
    return()
  endif ()

  # Enable code coverage.
  enclave_compile_options(${NAME} PRIVATE -g -O0 -fprofile-arcs -ftest-coverage)
  # Link against libgcov.
  enclave_link_libraries(${NAME} PRIVATE gcov)
endfunction (enclave_enable_code_coverage)
