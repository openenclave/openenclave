# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oehostfs STATIC hostfs.c)

maybe_build_using_clangw(oehostfs)

add_dependencies(oehostfs posix_trusted_edl)

target_include_directories(oehostfs PRIVATE
    ${CMAKE_SOURCE_DIR}/posix
    ${CMAKE_CURRENT_BINARY_DIR}/../..
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oehostfs oeposix)

install(TARGETS oehostfs EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
