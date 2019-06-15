# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oehostresolver STATIC hostresolver.c)

maybe_build_using_clangw(oehostresolver)

add_dependencies(oehostresolver syscall_trusted_edl)

target_include_directories(oehostresolver PRIVATE
    ${CMAKE_BINARY_DIR}/syscall
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oehostresolver oesyscall)

install(TARGETS oehostresolver EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
