# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_subdirectory(image)

add_test(tests/split ./host/split_host ./enc/split_enc ./image/image)
