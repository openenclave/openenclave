# Copyright (c) Open Enclave SDK contributors.
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
    if (UNIX)
        # Noop on Linux.
        return()
    endif()

    if (NOT OE_SGX OR NOT USE_CLANGW)
        return()
    endif()

    # Add compile options from compiler_settings.cmake
    if (COMMAND enclave_compile_options)
        # Currently `enclave_compile_options` is only for internal OE build.
        enclave_compile_options(${OE_TARGET} PRIVATE
            -Wall -Werror -Wpointer-arith -Wconversion -Wextra -Wno-missing-field-initializers
            -fno-strict-aliasing
            -mxsave
            -fno-builtin-malloc -fno-builtin-calloc -fno-builtin
            -mllvm -x86-speculative-load-hardening)
    else()
        target_compile_options(${OE_TARGET} PRIVATE
            -Wall -Werror -Wpointer-arith -Wconversion -Wextra -Wno-missing-field-initializers
            -fno-strict-aliasing
            -mxsave
            -fno-builtin-malloc -fno-builtin-calloc -fno-builtin
            -mllvm -x86-speculative-load-hardening)
    endif()

    # Setup library names variables
    set(CMAKE_STATIC_LIBRARY_PREFIX "lib" PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX ".a" PARENT_SCOPE)

    # Setup library tool variables
    set(CMAKE_C_CREATE_STATIC_LIBRARY 
        "\"${OE_BASH}\" \"${OE_SCRIPTSDIR}/llvm-arw\" \"qc <TARGET> <OBJECTS>\""
        PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY 
        "\"${OE_BASH}\" \"${OE_SCRIPTSDIR}/llvm-arw\" \"qc <TARGET> <OBJECTS>\""
        PARENT_SCOPE)

    # Setup linker variables.
    set(CMAKE_EXECUTABLE_SUFFIX "" PARENT_SCOPE)
    set(CMAKE_C_STANDARD_LIBRARIES "" PARENT_SCOPE)
    set(CMAKE_C_LINK_EXECUTABLE
        "\"${OE_BASH}\" \"${OE_SCRIPTSDIR}/clangw\" \"link <OBJECTS> -o <TARGET>  <LINK_LIBRARIES>\""
        PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_LIBRARIES "" PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE
        "\"${OE_BASH}\" \"${OE_SCRIPTSDIR}/clangw\" \"link <OBJECTS> -o <TARGET>  <LINK_LIBRARIES>\""
        PARENT_SCOPE)

    # Setup compiler variables.
    set(CMAKE_C_COMPILE_OBJECT
        "\"${OE_BASH}\" \"${OE_SCRIPTSDIR}/clangw\" \"<DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>\""
        PARENT_SCOPE)

    set(CMAKE_CXX_COMPILE_OBJECT
        "\"${OE_BASH}\" \"${OE_SCRIPTSDIR}/clangw\" \"<DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>\""
        PARENT_SCOPE)

    # Loop through assembly files in the list of sources in the
    # target and mark them as C files so that they will be compiled.
    # Otherwise .s and .S files will be ignored on Windows.
    get_target_property(SOURCES ${OE_TARGET} SOURCES)
    foreach(SRC IN LISTS SOURCES)
        if (${SRC} MATCHES ".S$" OR ${SRC} MATCHES ".s$")
            set_source_files_properties(${SRC} PROPERTIES
            LANGUAGE C
            # Prevent warnings due to C options passed to .s files.
            COMPILE_FLAGS -Wno-unused-command-line-argument)
        endif()
    endforeach()
endfunction(maybe_build_using_clangw)

