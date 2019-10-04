# Copyright (c) Microsoft Corporation. All rights reserved.
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
  # TODO: This copy command will fail if `esy` is used to build
  # locally (e.g., for development) as the folder gets too big with
  # the Node modules etc. We should be more explicit.
  COMMAND cmake -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND esy
  DEPENDS package.json
          dune-project
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
install(PROGRAMS ${BINARY}
  RENAME oeedger8r${CMAKE_EXECUTABLE_SUFFIX}
  DESTINATION ${CMAKE_INSTALL_BINDIR})
