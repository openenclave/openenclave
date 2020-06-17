# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(oelibcxx STATIC)

maybe_build_using_clangw(oelibcxx)

# NOTE: The three listed libraries are all `OBJECT` libraries, which
# is just a collection of objects known to CMake. By "linking" them
# here, we're actually combining all the objects into a single static
# library using CMake, which is portable. This also transitively pulls
# in all the public compile options, compile definitions, and include
# directories of these targets and their dependencies (such as
# `oelibc`). Hence this file has more comments than code.
enclave_link_libraries(oelibcxx PUBLIC libcxx libcxxrt libunwind)

set_enclave_property(TARGET oelibcxx PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/enclave)

install_enclaves(
  TARGETS
  oelibcxx
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
