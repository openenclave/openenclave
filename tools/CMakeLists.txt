# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(oeedger8r)

if (OE_SGX)
  add_subdirectory(oesgx)
  add_subdirectory(oesign)
endif ()
