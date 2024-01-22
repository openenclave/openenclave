# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# Add an enclave test to ensure that the enclave binaries are copied over.
add_enclave_test(tests/sgx/backtrace-ensure-enclave sgx_backtrace_host
                 sgx_backtrace_enc 0)

add_enclave_test(tests/sgx/backtrace-ensure-no-pfgp-enclave sgx_backtrace_host
                 sgx_backtrace_no_pfgp_enc 0)
add_test(
  NAME tests/sgx/backtrace
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ${OE_BASH} -c
          "OE_LOG_LEVEL=INFO host/sgx_backtrace_host enc/sgx_backtrace_enc 0")

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

add_test(
  NAME tests/sgx/backtrace_segfault
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ${OE_BASH} -c
          "OE_LOG_LEVEL=ERROR host/sgx_backtrace_host enc/sgx_backtrace_enc 1")

set_tests_properties(
  tests/sgx/backtrace_segfault
  PROPERTIES
    SKIP_RETURN_CODE
    2
    PASS_REGULAR_EXPRESSION
    "\
sgx_backtrace_enc:Segmentation fault.+\
_trigger_segfault.+\
ecall_enc_test_segfault.+\
oe_handle_call_enclave_function.+\
_handle_ecall.+\
oe_enter.+\
")

add_test(
  NAME tests/sgx/backtrace_abort_after_segfault
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND ${OE_BASH} -c
          "OE_LOG_LEVEL=INFO host/sgx_backtrace_host enc/sgx_backtrace_enc 2")

set_tests_properties(
  tests/sgx/backtrace_abort_after_segfault
  PROPERTIES
    SKIP_RETURN_CODE
    2
    PASS_REGULAR_EXPRESSION
    "\
oe_abort_with_td.+\
oe_abort.+\
test_print_abort_backtrace.+\
enc_test_abort_after_segfault.+\
ecall_enc_test_abort_after_segfault.+\
oe_handle_call_enclave_function.+\
_handle_ecall.+\
oe_enter.+\
")

add_test(
  NAME tests/sgx/backtrace_segfault_no_pf_gp
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND
    ${OE_BASH} -c
    "OE_LOG_LEVEL=INFO host/sgx_backtrace_host enc/sgx_backtrace_no_pfgp_enc 3")

set_tests_properties(
  tests/sgx/backtrace_segfault_no_pf_gp
  PROPERTIES SKIP_RETURN_CODE 2 PASS_REGULAR_EXPRESSION "\
Unhandled in-enclave exception.+\
")
