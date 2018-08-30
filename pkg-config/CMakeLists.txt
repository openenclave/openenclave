# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## oeenclave.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave.pc
    DESTINATION 
    /usr/local/share/pkgconfig)

##==============================================================================
##
## oeenclave++.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oeenclave++.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave++.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oeenclave++.pc
    DESTINATION 
    /usr/local/share/pkgconfig)

##==============================================================================
##
## oehost.pc:
##
##==============================================================================

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/oehost.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/oehost.pc
    DESTINATION 
    /usr/local/share/pkgconfig)

