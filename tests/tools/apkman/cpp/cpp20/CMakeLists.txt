# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

#add_enclave_test(tests/tools/apkman/cpp20 cpp20_host cpp20_enc)
