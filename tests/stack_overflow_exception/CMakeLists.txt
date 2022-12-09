# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/stack_overflow_exception stack_overflow_exception_host
                 sgx_stack_overflow_exception_enc_signed)

add_enclave_test(
  tests/stack_overflow_exception_unsigned stack_overflow_exception_host
  sgx_stack_overflow_exception_enc_unsigned)
