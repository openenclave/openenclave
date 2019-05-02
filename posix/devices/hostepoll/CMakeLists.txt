# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oehostepoll STATIC hostepoll.c)

maybe_build_using_clangw(oehostepoll)

add_dependencies(oehostepoll posix_trusted_edl)

target_include_directories(oehostepoll PRIVATE
    ${CMAKE_SOURCE_DIR}/posix/kernel/include
    ${CMAKE_CURRENT_BINARY_DIR}/../..
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oehostepoll oeposix)

install(TARGETS oehostepoll EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
