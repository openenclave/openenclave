# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Compile libcxx for Open Enclave. Some of these build rules emulate
# those found in the original sources, but instead this builds an
# OBJECT library in our CMake graph.

add_library(libcxxrt OBJECT
  libcxxrt/src/dynamic_cast.cc
  libcxxrt/src/exception.cc
  libcxxrt/src/guard.cc
  libcxxrt/src/stdexcept.cc
  libcxxrt/src/typeinfo.cc
  libcxxrt/src/memory.cc
  libcxxrt/src/auxhelper.cc
  libcxxrt/src/libelftc_dem_gnu3.c)

maybe_build_using_clangw(libcxxrt)

target_compile_options(libcxxrt PRIVATE -Wno-error)

target_compile_definitions(libcxxrt PRIVATE -D_GNU_SOURCE)

target_link_libraries(libcxxrt PUBLIC oelibc)

install(TARGETS libcxxrt EXPORT openenclave-targets)
