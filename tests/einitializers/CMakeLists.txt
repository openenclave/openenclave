# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enclib1)
  add_subdirectory(enclib2)
  add_subdirectory(enc)
endif()

add_enclave_test(tests/einitializers einitializers_host einitializers_enc)
