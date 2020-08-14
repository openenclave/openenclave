# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

set(ENCLAVE "./enc/region_enc")

add_test(tests/region ./host/region_host ${ENCLAVE})
