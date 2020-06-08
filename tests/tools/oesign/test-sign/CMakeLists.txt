# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OESIGN_TEST_INPUTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/../test-inputs)

configure_file(../sign-and-verify.py sign-and-verify.py COPYONLY)

add_custom_target(
  oesign_sign_test_dependencies ALL
  DEPENDS oesign oesign_test_host oesign_test_enc oesign_test_keys
          oesign_test_configs)

# Test oesign succeeds with valid short form of engine signing parameters
set(OESIGN_SIGN_VALID_SHORT_ARGS
    "-c ${OESIGN_TEST_INPUTS_DIR}/valid.conf -k ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem"
)

add_test(
  NAME tests/oesign-sign-valid-short-args
  COMMAND
    python sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --oesign-args ${OESIGN_SIGN_VALID_SHORT_ARGS})

set_tests_properties(
  tests/oesign-sign-valid-short-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Launch of signed enclave succeeded")

# Test oesign succeeds with valid long form of engine signing parameters
set(OESIGN_SIGN_VALID_LONG_ARGS
    "--config-file ${OESIGN_TEST_INPUTS_DIR}/valid.conf --key-file ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem"
)

add_test(
  NAME tests/oesign-sign-valid-long-args
  COMMAND
    python sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --oesign-args ${OESIGN_SIGN_VALID_LONG_ARGS})

set_tests_properties(
  tests/oesign-sign-valid-long-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Launch of signed enclave succeeded")

# Test invalid --config-file (-c) argument
add_test(
  NAME tests/oesign-sign-invalid-config-file
  COMMAND oesign sign -e $<TARGET_FILE:oesign_test_enc> -c does_not_exist.conf
          -k ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-invalid-config-file
  PROPERTIES PASS_REGULAR_EXPRESSION
             "ERROR: Failed to load configuration file: does_not_exist.conf")

# Test invalid --key-file (-k) argument
add_test(NAME tests/oesign-sign-invalid-key-file
         COMMAND oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
                 ${OESIGN_TEST_INPUTS_DIR}/valid.conf -k does_not_exist.pem)

set_tests_properties(
  tests/oesign-sign-invalid-key-file
  PROPERTIES PASS_REGULAR_EXPRESSION
             "ERROR: Failed to load file: does_not_exist.pem")

# Test signing key with invalid exponent for SGX signing
add_test(
  NAME tests/oesign-sign-invalid-key-exp
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/bad_exp_key.private.pem)

set_tests_properties(
  tests/oesign-sign-invalid-key-exp
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: oe_sgx_sign_enclave\\(\\) failed: result=OE_INVALID_SGX_SIGNING_KEY"
)

# Test invalid config file with negative NumHeapPages specified
add_test(
  NAME tests/oesign-sign-negative-num-heap-pages
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/negative_num_heap_pages.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-negative-num-heap-pages
  PROPERTIES PASS_REGULAR_EXPRESSION "bad value for 'NumHeapPages'")

# Test empty config file with unconfigured enclave
add_test(
  NAME tests/oesign-sign-empty-config
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/empty.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-empty-config
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: Invalid enclave property value: header.size_settings.num_tcs")
