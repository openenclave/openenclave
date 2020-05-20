# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

find_program(OCAMLOPT ocamlopt)

if (OCAMLOPT)
  set(BINARY ${CMAKE_CURRENT_BINARY_DIR}/oeedger8r${CMAKE_EXECUTABLE_SUFFIX})
  add_custom_command(
    OUTPUT ${BINARY}
    # Copy sources to build folder.
    COMMAND cmake -E copy ${CMAKE_CURRENT_SOURCE_DIR}/intel/*
            ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND cmake -E copy ${CMAKE_CURRENT_SOURCE_DIR}/src/*
            ${CMAKE_CURRENT_BINARY_DIR}
    # Generate lexer and parser.
    COMMAND ocamllex Lexer.mll
    COMMAND ocamlyacc Parser.mly
    # Generate Intel library.
    # Use -w -3 to suppress
    # warning 3: deprecated: String.lowercase
    COMMAND
      ocamlopt -c -bin-annot -for-pack Intel -w -3 Ast.ml Util.ml SimpleStack.ml
      Plugin.ml Preprocessor.ml Parser.mli Parser.ml Lexer.ml CodeGen.ml
    COMMAND ocamlopt -pack -o Intel.cmx Ast.cmx Util.cmx SimpleStack.cmx
            Plugin.cmx Preprocessor.cmx Parser.cmx Lexer.cmx CodeGen.cmx
    # Generate oeedger8r
    # Additionally suppress
    # Warning 40: input_files was selected from type Intel.Util.edger8r_params.
    # It is not visible in the current scope, and will not
    # be selected if the type becomes unknown.
    COMMAND
      ocamlopt -bin-annot str.cmxa unix.cmxa Intel.cmx -w -3-40 Common.mli
      Common.ml Headers.mli Headers.ml Sources.mli Sources.ml Emitter.ml main.ml
      -o ${BINARY}
    DEPENDS src/dune
            src/Common.mli
            src/Common.ml
            src/Headers.mli
            src/Headers.mli
            src/Sources.mli
            src/Sources.mli
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
            intel/Util.ml
            CMakeLists.txt)

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

  return()
endif ()

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
