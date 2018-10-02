# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## Rule for creating and installing the .openenclaverc script.
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/openenclaverc.in
    ${CMAKE_BINARY_DIR}/output/share/.openenclaverc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/.openenclaverc
    DESTINATION 
    "${CMAKE_INSTALL_DATADIR}")
