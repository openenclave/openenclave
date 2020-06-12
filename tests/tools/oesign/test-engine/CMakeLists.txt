# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oesign_test_engine SHARED oesign-test-engine.c)

target_include_directories(oesign_test_engine PRIVATE include)

set(OESIGN_TEST_INPUTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/../test-inputs)

configure_file(../sign-and-verify.py sign-and-verify.py COPYONLY)

add_custom_target(
  oesign_engine_test_dependencies ALL
  DEPENDS oesign oesign_test_host oesign_test_enc oesign_test_keys
          oesign_test_configs oesign_test_engine)

# Test oesign succeeds with valid short form of engine signing parameters
set(OESIGN_ENGINE_VALID_SHORT_ARGS
    "-c ${OESIGN_TEST_INPUTS_DIR}/valid.conf -n oesign-test-engine -p $<TARGET_FILE:oesign_test_engine> -i ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem"
)

add_test(
  NAME tests/oesign-engine-valid-short-args
  COMMAND
    python sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --oesign-args ${OESIGN_ENGINE_VALID_SHORT_ARGS})

set_tests_properties(
  tests/oesign-engine-valid-short-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Launch of signed enclave succeeded")

# Test oesign succeeds with valid long form of engine signing parameters
set(OESIGN_ENGINE_VALID_LONG_ARGS
    "--config-file ${OESIGN_TEST_INPUTS_DIR}/valid.conf --engine oesign-test-engine --load-path $<TARGET_FILE:oesign_test_engine> --key-id ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem"
)

add_test(
  NAME tests/oesign-engine-valid-long-args
  COMMAND
    python sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --oesign-args ${OESIGN_ENGINE_VALID_LONG_ARGS})

set_tests_properties(
  tests/oesign-engine-valid-long-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Launch of signed enclave succeeded")

# Test invalid --load-path (-p) argument
add_test(
  NAME tests/oesign-engine-invalid-load-path
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -n oesign-test-engine -p /tmp/no_there
    -i ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-engine-invalid-load-path
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: oe_sgx_sign_enclave_from_engine\\(\\) failed: result=OE_INVALID_PARAMETER"
)

# Test invalid --engine (-n) argument
add_test(
  NAME tests/oesign-engine-invalid-engine
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -n undefined-engine-id -p
    $<TARGET_FILE:oesign_test_engine> -i
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-engine-invalid-engine
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: oe_sgx_sign_enclave_from_engine\\(\\) failed: result=OE_INVALID_PARAMETER"
)

# Test invalid --key-id (-i) argument
add_test(
  NAME tests/oesign-engine-invalid-key-id
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -n oesign-test-engine -p
    $<TARGET_FILE:oesign_test_engine> -i bogus/key)

set_tests_properties(
  tests/oesign-engine-invalid-key-id
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: oe_sgx_sign_enclave_from_engine\\(\\) failed: result=OE_INVALID_PARAMETER"
)

# Test signing key with invalid exponent for SGX signing
add_test(
  NAME tests/oesign-engine-invalid-key-exp
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -n oesign-test-engine -p
    $<TARGET_FILE:oesign_test_engine> -i
    ${OESIGN_TEST_INPUTS_DIR}/bad_exp_key.private.pem)

set_tests_properties(
  tests/oesign-engine-invalid-key-exp
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: oe_sgx_sign_enclave_from_engine\\(\\) failed: result=OE_INVALID_SGX_SIGNING_KEY"
)
