# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/src
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/src

    # Rebuild if source changes
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Emitter.ml ${CMAKE_CURRENT_SOURCE_DIR}/intel/*.*
)

add_custom_command(
    OUTPUT ${OE_BINDIR}/oeedger8r     
    COMMAND make
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/src/_build/main.native ${OE_BINDIR}/oeedger8r
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/src
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src
)

add_custom_target(oeedger8r ALL
    DEPENDS ${OE_BINDIR}/oeedger8r      
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/src
)

# install rule
install (PROGRAMS ${OE_BINDIR}/oeedger8r DESTINATION ${CMAKE_INSTALL_BINDIR})
