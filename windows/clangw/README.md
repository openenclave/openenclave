# clangw : Clang Compiler Wrapper for building enclaves

clangw takes a mix of msvc and gcc/clang command-line agruments generated
by cmake on windows, transforms them to their clang equivalents and
then passes them along to clang.

It is similar to clang-cl. However clang-cl cannot be used for 
cross-compiling since it also does not understand options like -fPIC,
-fvisibility=hidden etc.
