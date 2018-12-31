# clangw : Clang Compiler Wrapper for building enclaves

clangw takes a mix of msvc and gcc/clang command-line agruments generated
by cmake on windows, transforms them to their clang equivalents and
then passes them along to clang.

It is similar to clang-cl. However clang-cl cannot be used for 
cross-compiling since it also does not understand options like -fPIC,
-fvisibility=hidden etc.

# llvm-arw: Wrapper for llvm-ar
Ninja generator uses response files when the command line is long.
However it uses / directory separator within the response files, which
llvm-ar does not handle. llvm-arw transforms all / to \ in both command line
as well as in repsponse files specified in the command-line.