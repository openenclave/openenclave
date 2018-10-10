# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# CMake project for reference manual
#
# Build and install reference manual. Disable with "ENABLE_REFMAN=OFF", such as when do Doxygen is installed.
#
# Target "refman-source" generates html-files into source-tree.
#
option(ENABLE_REFMAN "Enable refman build" ON)

include (ExternalProject)
find_package(Doxygen)

if(ENABLE_REFMAN AND NOT DOXYGEN_FOUND)
    message(FATAL_ERROR "Doxygen not found - specfify no refman refman generation with -DENABLE_REFMAN=OFF")
elseif(NOT ENABLE_REFMAN)
    message("ENABLE_REFMAN disabled, skipping refman generation")
else()
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doxygen.conf ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)

    ExternalProject_Add(refman
        DOWNLOAD_COMMAND ""
        COMMENT "Generating refman HTML documentation"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        INSTALL_COMMAND $(CMAKE_COMMAND) -E copy_directory
            html ${OE_DOCDIR}/openenclave/html
        BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()
