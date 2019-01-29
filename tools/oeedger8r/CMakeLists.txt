# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# NOTE: The custom commands below first copy the input files to the
# build directory and then invoke the OCaml tools because those tools
# do not emit to the current working directory, they always emit to
# the location of the input file.

# Generate Lexer.
find_program(OCAMLLEX ocamllex)
if (NOT OCAMLLEX)
  message(FATAL_ERROR "ocamllex not found! Please install 'ocaml-native-compilers'")
endif ()

add_custom_command(
  OUTPUT Lexer.ml
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/intel/Lexer.mll ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ocamllex Lexer.mll
  DEPENDS intel/Lexer.mll)

# Generate Parser.
find_program(OCAMLYACC ocamlyacc)
if (NOT OCAMLYACC)
  message(FATAL_ERROR "ocamlycac not found! Please install 'ocaml-native-compilers'")
endif ()

add_custom_command(
  OUTPUT Parser.ml Parser.mli
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/intel/Parser.mly ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ocamlyacc Parser.mly
  DEPENDS intel/Parser.mly)

# Compile
set(BINARY oeedger8r${CMAKE_EXECUTABLE_SUFFIX})
add_custom_command(
    OUTPUT ${BINARY}
    COMMAND ocamlopt -c -bin-annot -I . -o Ast.cmx          ${CMAKE_CURRENT_SOURCE_DIR}/intel/Ast.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Util.cmx         ${CMAKE_CURRENT_SOURCE_DIR}/intel/Util.ml
    COMMAND ocamlopt -c -bin-annot -I . -o SimpleStack.cmx  ${CMAKE_CURRENT_SOURCE_DIR}/intel/SimpleStack.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Plugin.cmx       ${CMAKE_CURRENT_SOURCE_DIR}/intel/Plugin.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Preprocessor.cmx ${CMAKE_CURRENT_SOURCE_DIR}/intel/Preprocessor.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Parser.cmi       ${CMAKE_CURRENT_BINARY_DIR}/Parser.mli
    COMMAND ocamlopt -c -bin-annot -I . -o Parser.cmx       ${CMAKE_CURRENT_BINARY_DIR}/Parser.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Lexer.cmx        ${CMAKE_CURRENT_BINARY_DIR}/Lexer.ml
    COMMAND ocamlopt -c -bin-annot -I . -o CodeGen.cmx      ${CMAKE_CURRENT_SOURCE_DIR}/intel/CodeGen.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Emitter.cmx      ${CMAKE_CURRENT_SOURCE_DIR}/Emitter.ml
    COMMAND ocamlopt -c -bin-annot -I . -o main.cmx         ${CMAKE_CURRENT_SOURCE_DIR}/main.ml
    COMMAND ocamlopt str.cmxa unix.cmxa Ast.cmx Util.cmx SimpleStack.cmx Plugin.cmx
                     Preprocessor.cmx Parser.cmx Lexer.cmx CodeGen.cmx Emitter.cmx main.cmx
                     -o ${BINARY}

    # Add dependency to generated Lexer and Parser, and all of the sources.
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Lexer.ml
            ${CMAKE_CURRENT_BINARY_DIR}/Parser.ml
            ${CMAKE_CURRENT_BINARY_DIR}/Parser.mli
            Emitter.ml
            main.ml
            intel/Ast.ml
            intel/CodeGen.ml
            intel/Edger8r.ml
            intel/Plugin.ml
            intel/Preprocessor.ml
            intel/SimpleStack.ml
            intel/Util.ml)

# The names here are important because the output file must be named
# `oeedger8r`, and our targets must not clash with that.
add_executable(edger8r IMPORTED GLOBAL)
set_target_properties(edger8r PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${BINARY})
add_custom_target(oeedger8r_target DEPENDS ${BINARY})
add_dependencies(edger8r oeedger8r_target)

# Can't use `install(TARGETS)` on an imported executable, because it
# causes CMake to crash with a segmentation fault.
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${BINARY} DESTINATION ${CMAKE_INSTALL_BINDIR})
