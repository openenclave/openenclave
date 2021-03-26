# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_test(tests/sgxextra ./host/sgxextra_host ./enc/sgxextra_enc)
