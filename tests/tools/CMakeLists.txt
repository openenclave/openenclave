# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (OE_SGX)
  if (UNIX)
    add_subdirectory(apkman)
  endif ()
  add_subdirectory(oecert)
  add_subdirectory(oecertdump)
  add_subdirectory(oesign)
endif ()
