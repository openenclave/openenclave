# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (NOT UNIX OR CMAKE_SYSTEM MATCHES "Linux-5*")
  add_subdirectory(oeapkman)
endif ()

if (OE_SGX)
  add_subdirectory(oecertdump)
  add_subdirectory(oesign)
  if (UNIX)
    add_subdirectory(oeseal)
  endif ()
endif ()
