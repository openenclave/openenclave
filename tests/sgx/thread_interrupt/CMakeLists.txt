# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/sgx/thread_interrupt_nonblocking thread_interrupt_host
                 sgx_thread_interrupt_enc nonblocking)
set_enclave_tests_properties(tests/sgx/thread_interrupt_nonblocking PROPERTIES
                             SKIP_RETURN_CODE 2)

add_enclave_test(tests/sgx/thread_interrupt_blocking thread_interrupt_host
                 sgx_thread_interrupt_enc blocking)
set_enclave_tests_properties(tests/sgx/thread_interrupt_blocking PROPERTIES
                             SKIP_RETURN_CODE 2)
