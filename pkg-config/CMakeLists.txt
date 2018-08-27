# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/openenclave.pc
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/openenclave.pc
    @ONLY)

install(FILES
    ${CMAKE_BINARY_DIR}/output/share/pkgconfig/openenclave.pc
    DESTINATION 
    /usr/local/share/pkgconfig)
