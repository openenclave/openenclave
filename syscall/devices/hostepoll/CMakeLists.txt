# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(oehostepoll STATIC hostepoll.c)

maybe_build_using_clangw(oehostepoll)

enclave_include_directories(oehostepoll PRIVATE
    ${CMAKE_BINARY_DIR}/syscall
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

enclave_link_libraries(oehostepoll oesyscall)

install_enclaves(TARGETS oehostepoll EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
