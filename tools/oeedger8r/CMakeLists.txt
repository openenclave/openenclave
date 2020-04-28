# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# NOTE: The custom commands below first copy the input files to the
# build directory and then invoke the OCaml tools because those tools
# do not emit to the current working directory, they always emit to
# the location of the input file.

find_program(ESY esy)
if (NOT ESY AND NOT USE_PLATFORM_OCAML)
  message(FATAL_ERROR "Please check your esy installation.\n")

elseif (NOT ESY) # USE_PLATFORM_OCAML
  # Use ocaml compilers if available.
  # Use ocaml compilers if available
  find_program(OCAMLLEX ocamllex)
  find_program(OCAMLYACC ocamlyacc)
  find_program(OCAMLOPT ocamlopt)
  if ((NOT OCAMLLEX) OR (NOT OCAMLYACC) OR (NOT OCAMLOPT))
     message(FATAL_ERROR "ocamllex, ocamlyacc or ocamlopt not found.\n"
                         "Install ocaml via your platform's package manager.")
  endif ()

  # Generate Lexer.
  add_custom_command(
    OUTPUT Lexer.ml
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/intel/Lexer.mll ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ocamllex Lexer.mll
    DEPENDS intel/Lexer.mll)

  # Generate Parser.
  add_custom_command(
    OUTPUT Parser.ml Parser.mli
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/intel/Parser.mly ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ocamlyacc Parser.mly
    DEPENDS intel/Parser.mly)

  # Compile
  set(BINARY  ${CMAKE_CURRENT_BINARY_DIR}/oeedger8r_main)
  add_custom_command(
    OUTPUT ${BINARY}
    COMMAND mkdir -p Intel
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o Ast.cmx          ${CMAKE_CURRENT_SOURCE_DIR}/intel/Ast.ml
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o Util.cmx         ${CMAKE_CURRENT_SOURCE_DIR}/intel/Util.ml
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o SimpleStack.cmx  ${CMAKE_CURRENT_SOURCE_DIR}/intel/SimpleStack.ml
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o Plugin.cmx       ${CMAKE_CURRENT_SOURCE_DIR}/intel/Plugin.ml
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o Preprocessor.cmx ${CMAKE_CURRENT_SOURCE_DIR}/intel/Preprocessor.ml
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o Parser.cmi       ${CMAKE_CURRENT_BINARY_DIR}/Parser.mli
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o Parser.oocmxl       ${CMAKE_CURRENT_BINARY_DIR}/Parser.ml
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o Lexer.cmx        ${CMAKE_CURRENT_BINARY_DIR}/Lexer.ml
    COMMAND ocamlopt -c -bin-annot -I . -for-pack Intel -o CodeGen.cmx      ${CMAKE_CURRENT_SOURCE_DIR}/intel/CodeGen.ml
    COMMAND ocamlopt -pack -o Intel.cmx Ast.cmx Util.cmx SimpleStack.cmx Plugin.cmx
                     Preprocessor.cmx Parser.cmx Lexer.cmx CodeGen.cmx
    COMMAND ocamlopt -c -bin-annot -I . -o Common.cmi      ${CMAKE_CURRENT_SOURCE_DIR}/src/Common.mli
    COMMAND ocamlopt -c -bin-annot -I . -o Common.cmx      ${CMAKE_CURRENT_SOURCE_DIR}/src/Common.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Headers.cmi      ${CMAKE_CURRENT_SOURCE_DIR}/src/Headers.mli
    COMMAND ocamlopt -c -bin-annot -I . -o Headers.cmx      ${CMAKE_CURRENT_SOURCE_DIR}/src/Headers.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Sources.cmi      ${CMAKE_CURRENT_SOURCE_DIR}/src/Sources.mli
    COMMAND ocamlopt -c -bin-annot -I . -o Sources.cmx      ${CMAKE_CURRENT_SOURCE_DIR}/src/Sources.ml
    COMMAND ocamlopt -c -bin-annot -I . -o Emitter.cmx     ${CMAKE_CURRENT_SOURCE_DIR}/src/Emitter.ml
    COMMAND ocamlopt -c -bin-annot -I . -o main.cmx        ${CMAKE_CURRENT_SOURCE_DIR}/src/main.ml
    COMMAND ocamlopt str.cmxa unix.cmxa Intel.cmx Common.cmx Headers.cmx Sources.cmx Emitter.cmx main.cmx -o ${BINARY}

    # Add dependency to generated Lexer and Parser, and all of the sources.
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/Lexer.ml
            ${CMAKE_CURRENT_BINARY_DIR}/Parser.ml
            ${CMAKE_CURRENT_BINARY_DIR}/Parser.mli
            src/Emitter.ml
            src/main.ml
            intel/Ast.ml
            intel/CodeGen.ml
            intel/Edger8r.ml
            intel/Plugin.ml
            intel/Preprocessor.ml
            intel/SimpleStack.ml
            intel/Util.ml)

  #add_custom_target(oeedger8r DEPENDS ${BINARY})
else()
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
  COMMAND cmake -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/esy.lock ${CMAKE_CURRENT_BINARY_DIR}/esy.lock
  COMMAND cmake -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/intel ${CMAKE_CURRENT_BINARY_DIR}/intel
  COMMAND cmake -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/src
  COMMAND cmake -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/dune-project ${CMAKE_CURRENT_SOURCE_DIR}/package.json ${CMAKE_CURRENT_BINARY_DIR}
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
endif ()

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
