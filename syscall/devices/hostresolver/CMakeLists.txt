# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(oehostresolver STATIC hostresolver.c)

maybe_build_using_clangw(oehostresolver)

enclave_include_directories(oehostresolver PRIVATE ${CMAKE_BINARY_DIR}/syscall
                            ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

enclave_enable_code_coverage(oehostresolver)

enclave_link_libraries(oehostresolver PRIVATE oesyscall)

install_enclaves(
  TARGETS
  oehostresolver
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
