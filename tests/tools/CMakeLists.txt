# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(oeapkman)

if (OE_SGX)
  add_subdirectory(oecertdump)
  add_subdirectory(oesign)
  add_subdirectory(oeseal)
endif ()
