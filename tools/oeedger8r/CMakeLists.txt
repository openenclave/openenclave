# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (WIN32)
    set(BINARY ${OE_BINDIR}/oeedger8r.exe)
else()
    set(BINARY ${OE_BINDIR}/oeedger8r)
    set(BUILD_COMMAND make)
endif()

# Note that we're dealing with OCaml sources instead of C/C++, so we have
# additional Makefiles that will handle the actual compilation / dependency
# management. As a result, we add every file to CMake and call the `make`
# command directly.
set(OEEDGER8R_SRC
    Emitter.ml
    main.ml
    Makefile
    intel/Ast.ml
    intel/CodeGen.ml
    intel/Edger8r.ml
    intel/Lexer.mll
    intel/Makefile
    intel/Parser.mly
    intel/Plugin.ml
    intel/Preprocessor.ml
    intel/SimpleStack.ml
    intel/Util.ml
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/src

    # Rebuild if source changes
    DEPENDS ${OEEDGER8R_SRC}
)

if (WIN32)
add_custom_command(
    OUTPUT ${BINARY}
    COMMAND C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell -command ${CMAKE_CURRENT_SOURCE_DIR}/build.ps1 ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} 
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/src/_build/main.native ${BINARY}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src
)
else()
 add_custom_command(
     OUTPUT ${BINARY}
     COMMAND ${BUILD_COMMAND}
     COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/src/_build/main.native ${BINARY}
     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src
     DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src
 )
endif()

add_custom_target(oeedger8r ALL
    DEPENDS ${BINARY}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src
)

# install rule
install (PROGRAMS ${BINARY} DESTINATION ${CMAKE_INSTALL_BINDIR})
