# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (WIN32)
    set(BINARY ${OE_BINDIR}/oeedger8r.exe)
else()
    set(BINARY ${OE_BINDIR}/oeedger8r)
endif()

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
add_custom_command(
    OUTPUT ${BINARY}
    COMMAND ocamlopt -c -I . -o Ast.cmx ${CMAKE_CURRENT_SOURCE_DIR}/intel/Ast.ml
    COMMAND ocamlopt -c -I . -o Util.cmx ${CMAKE_CURRENT_SOURCE_DIR}/intel/Util.ml
    COMMAND ocamlopt -c -I . -o SimpleStack.cmx ${CMAKE_CURRENT_SOURCE_DIR}/intel/SimpleStack.ml
    COMMAND ocamlopt -c -I . -o Plugin.cmx ${CMAKE_CURRENT_SOURCE_DIR}/intel/Plugin.ml
    COMMAND ocamlopt -c -I . -o Preprocessor.cmx ${CMAKE_CURRENT_SOURCE_DIR}/intel/Preprocessor.ml
    COMMAND ocamlopt -c -I . -o Parser.cmi ${CMAKE_CURRENT_BINARY_DIR}/Parser.mli
    COMMAND ocamlopt -c -I . -o Parser.cmx ${CMAKE_CURRENT_BINARY_DIR}/Parser.ml
    COMMAND ocamlopt -c -I . -o Lexer.cmx ${CMAKE_CURRENT_BINARY_DIR}/Lexer.ml
    COMMAND ocamlopt -c -I . -o CodeGen.cmx ${CMAKE_CURRENT_SOURCE_DIR}/intel/CodeGen.ml
    COMMAND ocamlopt -c -I . -o Emitter.cmx ${CMAKE_CURRENT_SOURCE_DIR}/Emitter.ml
    COMMAND ocamlopt -c -I . -o main.cmx ${CMAKE_CURRENT_SOURCE_DIR}/main.ml
    COMMAND ocamlopt -c -I . -o Emitter.cmx ${CMAKE_CURRENT_SOURCE_DIR}/Emitter.ml
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
            intel/Util.ml
)

add_custom_target(oeedger8r ALL DEPENDS ${BINARY})

# install rule
install (PROGRAMS ${BINARY} DESTINATION ${CMAKE_INSTALL_BINDIR})
