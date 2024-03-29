# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OESIGN_TEST_INPUTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/../test-inputs)

add_custom_command(
  OUTPUT sign-and-verify.py
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../sign-and-verify.py
  COMMAND cmake -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../sign-and-verify.py
          ${CMAKE_CURRENT_BINARY_DIR})

add_custom_target(
  oesign_sign_test_dependencies ALL
  DEPENDS oesign oesign_test_host oesign_test_enc oesign_test_keys
          oesign_test_configs sign-and-verify.py)

# Test oesign succeeds with valid short form of engine signing parameters
set(OESIGN_SIGN_VALID_SHORT_ARGS
    "[-c,${OESIGN_TEST_INPUTS_DIR}/valid.conf,-k,${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem,-o,test_enclave.signed]"
)

add_test(
  NAME tests/oesign-sign-valid-short-args
  COMMAND
    ${PYTHON} sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --oesign-args ${OESIGN_SIGN_VALID_SHORT_ARGS})

set_tests_properties(
  tests/oesign-sign-valid-short-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Signed enclave test app succeeded")

# Test oesign succeeds with valid long form of engine signing parameters
set(OESIGN_SIGN_VALID_LONG_ARGS
    "[--config-file,${OESIGN_TEST_INPUTS_DIR}/valid.conf,--key-file,${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem,--output-file,test_enclave.signed]"
)

add_test(
  NAME tests/oesign-sign-valid-long-args
  COMMAND
    ${PYTHON} sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --oesign-args ${OESIGN_SIGN_VALID_LONG_ARGS})

set_tests_properties(
  tests/oesign-sign-valid-long-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Signed enclave test app succeeded")

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

# Test invalid .conf with duplicate Debug property
add_test(
  NAME tests/oesign-sign-duplicate-debug-config
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/duplicate_debug.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-duplicate-debug-config
  PROPERTIES PASS_REGULAR_EXPRESSION "Duplicate 'Debug' value provided")

# Test invalid .conf with duplicate NumHeapPages property
add_test(
  NAME tests/oesign-sign-duplicate-num-heap-pages-config
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/duplicate_num_heap_pages.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-duplicate-num-heap-pages-config
  PROPERTIES PASS_REGULAR_EXPRESSION "Duplicate 'NumHeapPages' value provided")

# Test invalid .conf with duplicate NumStackPages property
add_test(
  NAME tests/oesign-sign-duplicate-num-stack-pages-config
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/duplicate_num_stack_pages.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-duplicate-num-stack-pages-config
  PROPERTIES PASS_REGULAR_EXPRESSION "Duplicate 'NumStackPages' value provided")

# Test invalid .conf with duplicate NumTCS property
add_test(
  NAME tests/oesign-sign-duplicate-num-tcs-config
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/duplicate_num_tcs.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-duplicate-num-tcs-config
  PROPERTIES PASS_REGULAR_EXPRESSION "Duplicate 'NumTCS' value provided")

# Test invalid .conf with duplicate ProductID property
add_test(
  NAME tests/oesign-sign-duplicate-product-id-config
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/duplicate_product_id.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-duplicate-product-id-config
  PROPERTIES PASS_REGULAR_EXPRESSION "Duplicate 'ProductID' value provided")

# Test invalid .conf with duplicate SecurityVersion property
add_test(
  NAME tests/oesign-sign-duplicate-security-version-config
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/duplicate_security_version.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-duplicate-security-version-config
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Duplicate 'SecurityVersion' value provided")

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

# Test invalid config file with invalid debug value specified
add_test(
  NAME tests/oesign-sign-debug-out-of-range
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/debug_out_of_range.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-debug-out-of-range
  PROPERTIES PASS_REGULAR_EXPRESSION "'Debug' value must be 0 or 1")

# Test invalid config file with invalid syntax "Debug" --> "debug"
add_test(
  NAME tests/oesign-sign-lowercase-debug-property
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/lowercase_debug_property.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(tests/oesign-sign-lowercase-debug-property
                     PROPERTIES PASS_REGULAR_EXPRESSION "unknown setting")

# Test valid kss properties argument
set(OESIGN_SIGN_VALID_KSS
    "[-c,${OESIGN_TEST_INPUTS_DIR}/kss_valid.conf,-k,${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem]"
)

add_test(
  NAME tests/oesign-sign-valid-kss
  COMMAND
    ${PYTHON} sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --oesign-args ${OESIGN_SIGN_VALID_KSS})

set_tests_properties(
  tests/oesign-sign-valid-kss
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Signed enclave test app succeeded")

# Test invalid kss properties argument ExtendedProductID too long
add_test(
  NAME tests/oesign-sign-extprodid-toolong
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/ext_prod_id_too_long.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-extprodid-toolong
  PROPERTIES PASS_REGULAR_EXPRESSION "bad value for 'ExtendedProductID'")

# Test invalid kss properties argument ExtendedProductID too short
add_test(
  NAME tests/oesign-sign-extprodid-tooshort
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/ext_prod_id_too_short.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-extprodid-tooshort
  PROPERTIES PASS_REGULAR_EXPRESSION "bad value for 'ExtendedProductID'")

# Test invalid kss properties argument ExtendedProductID too short
add_test(
  NAME tests/oesign-sign-familyid-toolong
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/family_id_too_long.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-familyid-toolong PROPERTIES PASS_REGULAR_EXPRESSION
                                                "bad value for 'FamilyID'")

# Test invalid kss properties argument FamilyID too short
add_test(
  NAME tests/oesign-sign-familyid-tooshort
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/family_id_too_short.conf -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-sign-familyid-tooshort PROPERTIES PASS_REGULAR_EXPRESSION
                                                 "bad value for 'FamilyID'")

if (ENABLE_ZERO_BASE_TESTS)
  # Test enclave creation at 0-base
  add_test(
    NAME tests/oesign-create-zero-base
    COMMAND
      oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
      ${OESIGN_TEST_INPUTS_DIR}/create_zero_base_enclave.conf -k
      ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

  set_tests_properties(
    tests/oesign-create-zero-base
    PROPERTIES PASS_REGULAR_EXPRESSION "Created;Test not run."
               FAIL_REGULAR_EXPRESSION "ERROR;Fail;Error")

  add_test(
    NAME tests/oesign-create-zero-base-start-address
    COMMAND
      oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
      ${OESIGN_TEST_INPUTS_DIR}/create_zero_base_enclave_w_start_address.conf
      -k ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

  set_tests_properties(
    tests/oesign-create-zero-base-start-address
    PROPERTIES PASS_REGULAR_EXPRESSION "Created;Test not run."
               FAIL_REGULAR_EXPRESSION "ERROR;Fail;Error")
endif ()
