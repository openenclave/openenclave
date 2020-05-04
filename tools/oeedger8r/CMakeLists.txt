# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# NOTE: The custom commands below first copy the input files to the
# build directory and then invoke the OCaml tools because those tools
# do not emit to the current working directory, they always emit to
# the location of the input file.

find_program(ESY esy)
if (NOT ESY)
  message(FATAL_ERROR "Please check your esy installation")
endif ()

# An artifact of using `esy` is that the generated binary is always
# `main.exe` regardless of platform. We rename it for installation in
# the package.
set(BINARY ${CMAKE_CURRENT_BINARY_DIR}/_build/default/src/main.exe)
add_custom_command(
  OUTPUT ${BINARY}
  # NOTE: We copy only the files we need to build in order to allow
  # for developers to build in the source tree (as this is easier for
  # testing changes and new packages and formatting etc.). We cannot
  # just copy the entire folder as CMake crashes with the
  # `node_modules`.
  COMMAND cmake -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/esy.lock
          ${CMAKE_CURRENT_BINARY_DIR}/esy.lock
  COMMAND cmake -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/intel
          ${CMAKE_CURRENT_BINARY_DIR}/intel
  COMMAND cmake -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${CMAKE_CURRENT_BINARY_DIR}/src
  COMMAND cmake -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/dune-project
          ${CMAKE_CURRENT_SOURCE_DIR}/package.json ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND esy install
  COMMAND esy build --release
  DEPENDS dune-project
          package.json
          src/dune
          src/Emitter.ml
          src/main.ml
          intel/dune
          intel/Ast.ml
          intel/CodeGen.ml
          intel/Edger8r.ml
          intel/Lexer.mll
          intel/Parser.mly
          intel/Plugin.ml
          intel/Preprocessor.ml
          intel/SimpleStack.ml
          intel/Util.ml)

# The names here are important because the output file must be named
# `oeedger8r`, and our targets must not clash with that.
add_executable(edger8r IMPORTED GLOBAL)
set_target_properties(edger8r PROPERTIES IMPORTED_LOCATION ${BINARY})
add_custom_target(oeedger8r_target DEPENDS ${BINARY})
add_dependencies(edger8r oeedger8r_target)

# Can't use `install(TARGETS)` on an imported executable, because it
# causes CMake to crash. Instead, see `openenclave-config.cmake.in`
# for the manual "export" of this target.
install(
  PROGRAMS ${BINARY}
  RENAME oeedger8r${CMAKE_EXECUTABLE_SUFFIX}
  DESTINATION ${CMAKE_INSTALL_BINDIR})
