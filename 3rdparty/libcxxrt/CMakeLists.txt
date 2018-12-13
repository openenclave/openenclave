# Copyright (c) Microsoft Corporation. All rights reserved.
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

set_source_files_properties(
  libcxxrt/src/dynamic_cast.cc
  PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion"
)

set_source_files_properties(
  libcxxrt/src/exception.cc
  PROPERTIES COMPILE_FLAGS "-Wno-unused-variable -Wno-conversion")

set_source_files_properties(
  libcxxrt/src/libelftc_dem_gnu3.c
  PROPERTIES COMPILE_FLAGS "-Wno-conversion"
)

set_target_properties(libcxxrt PROPERTIES
  POSITION_INDEPENDENT_CODE ON)

target_compile_options(libcxxrt PRIVATE -Wno-tautological-compare)

target_compile_definitions(libcxxrt PRIVATE -D_GNU_SOURCE)

target_link_libraries(libcxxrt PUBLIC oelibc)
