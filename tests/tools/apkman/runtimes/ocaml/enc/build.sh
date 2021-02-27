#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

rm -rf ocaml 2> /dev/null
rm -f ocamlprogram.a 2> /dev/null
mkdir ocaml && cd ocaml || exit 1
SRC_DIR=$(dirname "$0")
cp "$SRC_DIR/lexer.mll" .
cp "$SRC_DIR/parser.mly" .
cp "$SRC_DIR/program.ml" .

ocamllex lexer.mll
ocamlyacc parser.mly
ocamlc parser.mli
ocamlc -custom -output-obj -o lexer.o lexer.ml
ocamlc -custom -output-obj -o parser.o parser.ml
ocamlc -custom -output-obj -o calc.o parser.cmo lexer.cmo program.ml
ocamlc -c -g "$SRC_DIR/modwrap.c"
cp "$(ocamlc -where)/libcamlrun.a" ocamlprogram.a && chmod +w ocamlprogram.a
ar r ocamlprogram.a calc.o modwrap.o
cp ocamlprogram.a ../
