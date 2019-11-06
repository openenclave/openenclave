# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oehostfs STATIC hostfs.c)

maybe_build_using_clangw(oehostfs)

add_dependencies(oehostfs syscall_trusted_edl)

target_include_directories(oehostfs PRIVATE
    ${CMAKE_BINARY_DIR}/syscall
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oehostfs oesyscall)

install(TARGETS oehostfs EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
