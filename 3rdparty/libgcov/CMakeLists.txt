# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

check_submodule_not_empty(compiler-rt)

apply_patches(patches compiler-rt)

add_enclave_library(
  gcov
  STATIC
  # Only the following three files are required to support GCOV-based code coverage analysis.
  compiler-rt/lib/profile/GCDAProfiling.c
  compiler-rt/lib/profile/InstrProfiling.c
  compiler-rt/lib/profile/InstrProfilingUtil.c)

maybe_build_using_clangw(gcov)

enclave_compile_options(gcov PRIVATE -Wno-error)

enclave_link_libraries(gcov PRIVATE oelibc oehostfs)

enclave_include_directories(gcov PRIVATE src)

install_enclaves(
  TARGETS
  gcov
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
