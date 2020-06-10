# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/atexit_ocall_single atexit_host atexit_enc 0)
add_enclave_test(tests/atexit_ocall_multiple atexit_host atexit_enc 1)
add_enclave_test(tests/atexit_ocall_ecall atexit_host atexit_enc 2)
