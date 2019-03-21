# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oehostfshost STATIC hostfs.c)

target_include_directories(oehostfshost PRIVATE 
    ${PROJECT_SOURCE_DIR}/include)

set_property(TARGET oehostfshost 
    PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

install(TARGETS oehostfshost EXPORT openenclave-targets 
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
