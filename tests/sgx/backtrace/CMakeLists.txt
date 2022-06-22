# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# Add an enclave test to ensure that the enclave binaries are copied over.
add_enclave_test(tests/sgx/backtrace-ensure-enclave sgx_backtrace_host
                 sgx_backtrace_enc)

add_test(
  NAME tests/sgx/backtrace
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ${OE_BASH} -c
          "OE_LOG_LEVEL=INFO host/sgx_backtrace_host enc/sgx_backtrace_enc")

set_tests_properties(
  tests/sgx/backtrace
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "\
test_print_backtrace.+\
enc_test.+\
ecall_enc_test.+\
oe_handle_call_enclave_function.+\
oe_abort.+\
test_print_abort_backtrace.+\
enc_test.+\
ecall_enc_test.+\
oe_handle_call_enclave_function.+\
")
