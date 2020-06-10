# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# Test that enclaves without tdata can be loaded
add_enclave_test(tests/thread_locals_no_tdata no_tdata_host no_tdata_enc)
