# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oelibcxx STATIC)

# NOTE: The three listed libraries are all `OBJECT` libraries, which
# is just a collection of objects known to CMake. By "linking" them
# here, we're actually combining all the objects into a single static
# library using CMake, which is portable. This also transitively pulls
# in all the public compile options, compile definitions, and include
# directories of these targets and their dependencies (such as
# `oelibc`). Hence this file has more comments than code.
target_link_libraries(oelibcxx
  PUBLIC libcxx libcxxrt libunwind)

set_property(TARGET oelibcxx
  PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/enclave)

install(TARGETS oelibcxx EXPORT openenclave
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
