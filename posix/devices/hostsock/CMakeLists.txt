# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oehostsock STATIC hostsock.c)

maybe_build_using_clangw(oehostsock)

add_dependencies(oehostsock posix_trusted_edl)

target_include_directories(oehostsock PRIVATE
    ${CMAKE_SOURCE_DIR}/posix/base/include
    ${CMAKE_BINARY_DIR}/posix/base
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oehostsock oeposix)

install(TARGETS oehostsock EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
