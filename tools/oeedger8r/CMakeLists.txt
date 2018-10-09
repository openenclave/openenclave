# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (WIN32)
    set(BINARY ${OE_BINDIR}/oeedger8r.exe)
    set(BUILD_COMMAND ocaml-env exec -- cmd.exe /c make)
else()
    set(BINARY ${OE_BINDIR}/oeedger8r)
    set(BUILD_COMMAND make)
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/src

    # Rebuild if source changes
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.ml ${CMAKE_CURRENT_SOURCE_DIR}/intel/*.* Makefile
)

add_custom_command(
    OUTPUT ${BINARY}
    COMMAND ${BUILD_COMMAND}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/src/_build/main.native ${BINARY}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src
)

add_custom_target(oeedger8r ALL
    DEPENDS ${BINARY}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src
)

# install rule
install (PROGRAMS ${BINARY} DESTINATION ${CMAKE_INSTALL_BINDIR})
