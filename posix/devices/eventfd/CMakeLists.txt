# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeeventfd STATIC eventfd.c)

maybe_build_using_clangw(oeeventfd)

add_dependencies(oeeventfd posix_trusted_edl)

target_include_directories(oeeventfd PRIVATE
    ${CMAKE_BINARY_DIR}/posix
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oeeventfd oeposix)

install(TARGETS oeeventfd EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
