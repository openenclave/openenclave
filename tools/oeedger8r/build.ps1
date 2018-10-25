# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. 

[CmdletBinding(DefaultParameterSetName="Standard")]
Param(
    [string]
    [ValidateNotNullOrEmpty()]
    $srcdir,
    [string]
    [ValidateNotNullOrEmpty()]
    $dstdir
)
$source_files = @( "Ast", 
        "Util", 
        "Parser", 
        "Lexer", 
        "Plugin", 
        "Preprocessor", 
        "SimpleStack", 
        "CodeGen", 
        "Edger8r" )

try {
    New-Item -Path "$dstdir" -Name "src" -ItemType "directory"
    New-Item -Path "$dstdir/src" -Name "_build" -ItemType "directory"
}
catch {
    Write-Output "error $_"
    Write-Host "error $_"
}

copy-item -recurse -Path "$srcdir/intel/*.ml*" -Destination "$dstdir/src/_build"
pushd $dstdir/src/_build

ocamllex.opt -q Lexer.mll
ocamlyacc Parser.mly

foreach ($i in @("Lexer", "Util", "Plugin", "Preprocessor","SimpleStack", "Ast", "CodeGen", "Edger8r")) {
    ocamldep.opt -modules "$i.ml" > "$i.ml.depends"
}
ocamldep.opt -modules Parser.mli > Parser.mli.depends

ocamlc.opt -c -o Ast.cmo Ast.ml
ocamlc.opt -c -o Parser.cmi Parser.mli

foreach ($i in @("Lexer", "Util", "Plugin", "Preprocessor","SimpleStack", "CodeGen", "Edger8r")) {
    ocamlc.opt -c -o "$i.cmo" "$i.ml"
}
ocamldep.opt -modules Parser.ml > Parser.ml.depends

foreach ($i in $source_files) {
    ocamlopt.opt -c -o "$i.cmx" "$i.ml"
}
ocamlopt.opt str.cmxa unix.cmxa Ast.cmx Util.cmx Parser.cmx Lexer.cmx Plugin.cmx Preprocessor.cmx SimpleStack.cmx CodeGen.cmx Edger8r.cmx -o main.native
popd
