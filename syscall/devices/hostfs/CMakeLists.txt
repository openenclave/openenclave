# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(oehostfs STATIC hostfs.c)

maybe_build_using_clangw(oehostfs)

enclave_include_directories(oehostfs PRIVATE ${CMAKE_BINARY_DIR}/syscall
                            ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

enclave_enable_code_coverage(oehostfs)

enclave_link_libraries(oehostfs PRIVATE oesyscall)

install_enclaves(
  TARGETS
  oehostfs
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
