# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/switchless_atexit_calls switchless_atexit_calls_host
                 sgx_switchless_atexit_calls_enc)
