# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper function to create ELF enclaves and libraries on Windows by 
# cross-compiling using a clang-wrapper. Noop on non Win32.
#
# Usage:
#
#  maybe_build_using_clangw(<target>)
#
# Given <target>, this function overrides the necessary cmake variables
# inorder to compile the given target using a clang-wrapper to produce
# ELF libraries and enclaves.
# In Windows, we use the "NMake Makefiles" or "Visual Studio 15 2017 Win64"
# generators which results in all the targets to be configured for MSVC.
# Calling maybe_build_using_clangw overides specific variables of the 
# target so that it is cross-compiled using clang to produce ELF libraries
# and enclaves. This approach is needed because there is no easy way
# to tell cmake to use one toolchain (msvc) for the host and another
# toolchain (clang cross-compiler) for enclaves. (It is possible in theory
# using external-projects. However that would require a significant 
# rewrite of the build system CMakeLists.)
#
function(maybe_build_using_clangw OE_TARGET)    
    if (NOT WIN32)
        # Noop on Linux.
        return()
    endif()

    if (NOT USE_CLANGW)
        return()
    endif()

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

    # Loop through assembley files in the list of sources in the
    # target and mark them as ASM files so that they will be compiled.
    # Otherwise .s and .S files will be ignored on Windows.
    get_target_property(SOURCES ${OE_TARGET} SOURCES)
    foreach(SRC IN LISTS SOURCES)
        if (${SRC} MATCHES ".S$" OR ${SRC} MATCHES ".s$")
            set_source_files_properties(${SRC} PROPERTIES LANGUAGE C)
        endif()
    endforeach()
endfunction(maybe_build_using_clangw)
