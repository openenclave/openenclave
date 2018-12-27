# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Build a given target using clang wrapper.
# This function overrides variable in the caller scope.
function(build_using_clangw OE_TARGET)
    # Add dependency to the clang wrapper
    add_dependencies(${OE_TARGET} clangw)

    # Add compile options from compiler_settings.cmake
    target_compile_options(${OE_TARGET} PRIVATE
        -Wall -Werror -Wpointer-arith -Wconversion -Wextra -Wno-missing-field-initializers
        -fno-strict-aliasing
        -mxsave
        -fno-builtin-malloc -fno-builtin-calloc)

    # Setup library names variables
    set(CMAKE_STATIC_LIBRARY_PREFIX "lib" PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX ".a" PARENT_SCOPE)

    # Setup library tool variables
    set(CMAKE_C_CREATE_STATIC_LIBRARY "llvm-ar qc <TARGET> <OBJECTS>" PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY "llvm-ar qc <TARGET> <OBJECTS>" PARENT_SCOPE)

    # Setup linker variables.
    find_program(LD_LLD "ld.lld.exe")
    set(CMAKE_EXECUTABLE_SUFFIX "" PARENT_SCOPE)
    set(CMAKE_C_STANDARD_LIBRARIES "" PARENT_SCOPE)
    set(CMAKE_C_LINK_EXECUTABLE
        "clang -target x86_64-pc-linux <OBJECTS> -o <TARGET>  <LINK_LIBRARIES> -fuse-ld=\"${LD_LLD}\""
        PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_LIBRARIES "" PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE
        "clang -target x86_64-pc-linux <OBJECTS> -o <TARGET>  <LINK_LIBRARIES> -fuse-ld=\"${LD_LLD}\""
        PARENT_SCOPE)

    # Setup comiler variables.
    set(CMAKE_C_COMPILE_OBJECT
        "\"${CMAKE_BINARY_DIR}/windows/clangw/clangw.exe\" -target x86_64-pc-linux <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>"
        PARENT_SCOPE)

    set(CMAKE_CXX_COMPILE_OBJECT
        "\"${CMAKE_BINARY_DIR}/windows/clangw/clangw.exe\" -target x86_64-pc-linux <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>"
        PARENT_SCOPE)

    # Change ASM file extension.
    # TODO: Do this very early so that this can be used instead of the
    # hack where we set the language of these files to C every time.
    #
    # set(CMAKE_ASM_SOURCE_FILE_EXTENSIONS ".s,.S")
    #
    # TODO: Change output extension to .o for enclaves.
    # The following does not work.
    # set(CMAKE_C_OUTPUT_EXTENSION ".o")
endfunction(build_using_clangw)
