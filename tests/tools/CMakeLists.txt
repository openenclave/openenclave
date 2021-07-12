# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (OE_SGX)
  if (UNIX)
    add_subdirectory(oeapkman)
  endif ()
  add_subdirectory(oecertdump)
  add_subdirectory(oesign)
endif ()
