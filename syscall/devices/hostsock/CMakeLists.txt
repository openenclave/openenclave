# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(oehostsock STATIC hostsock.c)

maybe_build_using_clangw(oehostsock)

enclave_include_directories(oehostsock PRIVATE ${CMAKE_BINARY_DIR}/syscall
                            ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

enclave_enable_code_coverage(oehostsock)

enclave_link_libraries(oehostsock PRIVATE oesyscall)

install_enclaves(
  TARGETS
  oehostsock
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
