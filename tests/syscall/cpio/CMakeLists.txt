# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_enclave_library(oecpio STATIC commands.c cpio.c strarr.c)

  enclave_link_libraries(oecpio PRIVATE oelibc oecore)

  maybe_build_using_clangw(oecpio)
endif ()
