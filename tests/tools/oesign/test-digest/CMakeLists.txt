# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OESIGN_TEST_INPUTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/../test-inputs)

add_custom_command(
  OUTPUT sign-and-verify.py
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../sign-and-verify.py
  COMMAND cmake -E copy ${CMAKE_CURRENT_SOURCE_DIR}/../sign-and-verify.py
          ${CMAKE_CURRENT_BINARY_DIR})

add_custom_command(
  OUTPUT oesign_test_enc.baseline.digest.sig
  DEPENDS oesign_test_enc oesign_test_configs oesign_test_keys
  COMMAND
    oesign digest -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -d oesign_test_enc.baseline.digest
  COMMAND
    openssl pkeyutl -sign -pkeyopt digest:sha256 -in
    oesign_test_enc.baseline.digest -inkey
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem -keyform PEM -out
    oesign_test_enc.baseline.digest.sig)

add_custom_command(
  OUTPUT oesign_test_alt_enc.baseline.digest.sig
  DEPENDS oesign_test_alt_enc
  COMMAND oesign digest -e $<TARGET_FILE:oesign_test_alt_enc> -d
          oesign_test_alt_enc.baseline.digest
  COMMAND
    openssl pkeyutl -sign -pkeyopt digest:sha256 -in
    oesign_test_alt_enc.baseline.digest -inkey
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem -keyform PEM -out
    oesign_test_alt_enc.baseline.digest.sig)

add_custom_target(
  oesign_digest_test_dependencies ALL
  DEPENDS oesign
          oesign_test_host
          oesign_test_enc
          oesign_test_enc.baseline.digest.sig
          oesign_test_alt_enc
          oesign_test_alt_enc.baseline.digest.sig
          oesign_test_keys
          oesign_test_configs
          sign-and-verify.py)

# Test digest sign commands with valid short form of arguments succeed
set(OESIGN_PKEYUTL_ARGS
    "[-in,oesign_test_enc.digest,-inkey,${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem,-keyform,PEM,-out,oesign_test_enc.digest.sig]"
)
set(OESIGN_SIGN_VALID_SHORT_ARGS
    "[-c,${OESIGN_TEST_INPUTS_DIR}/valid.conf,-d,oesign_test_enc.digest.sig,-x,${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem]"
)
set(OESIGN_DIGEST_VALID_SHORT_ARGS
    "[-c,${OESIGN_TEST_INPUTS_DIR}/valid.conf,-d,oesign_test_enc.digest]")

add_test(
  NAME tests/oesign-digest-valid-short-args
  COMMAND
    python sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --digest-args ${OESIGN_DIGEST_VALID_SHORT_ARGS}
    --pkeyutl-args ${OESIGN_PKEYUTL_ARGS} --oesign-args
    ${OESIGN_SIGN_VALID_SHORT_ARGS})

set_tests_properties(
  tests/oesign-digest-valid-short-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Launch of signed enclave succeeded")

# Test digest sign commands with valid long form of arguments succeed
set(OESIGN_SIGN_VALID_LONG_ARGS
    "[--config-file,${OESIGN_TEST_INPUTS_DIR}/valid.conf,--digest-signature,oesign_test_enc.digest.sig,--x509,${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem]"
)
set(OESIGN_DIGEST_VALID_LONG_ARGS
    "[--config-file,${OESIGN_TEST_INPUTS_DIR}/valid.conf,--digest-file,oesign_test_enc.digest]"
)

add_test(
  NAME tests/oesign-digest-valid-long-args
  COMMAND
    python sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_enc> --oesign-path
    $<TARGET_FILE:oesign> --digest-args ${OESIGN_DIGEST_VALID_LONG_ARGS}
    --pkeyutl-args ${OESIGN_PKEYUTL_ARGS} --oesign-args
    ${OESIGN_SIGN_VALID_LONG_ARGS})

set_tests_properties(
  tests/oesign-digest-valid-long-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Launch of signed enclave succeeded")

# Test digest sign commands without --config-file (-c) argument on preconfigured enclave succeeds
set(OESIGN_PKEYUTL_DEV_CONFIG_ARGS
    "[-in,oesign_test_alt_enc.digest,-inkey,${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem,-keyform,PEM,-out,oesign_test_alt_enc.digest.sig]"
)
set(OESIGN_SIGN_VALID_DEV_CONFIG_ARGS
    "[--digest-signature,oesign_test_alt_enc.digest.sig,--x509,${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem]"
)
set(OESIGN_DIGEST_VALID_DEV_CONFIG_ARGS
    "[--digest-file,oesign_test_alt_enc.digest]")

add_test(
  NAME tests/oesign-digest-valid-dev-config-args
  COMMAND
    python sign-and-verify.py --host-path $<TARGET_FILE:oesign_test_host>
    --enclave-path $<TARGET_FILE:oesign_test_alt_enc> --oesign-path
    $<TARGET_FILE:oesign> --digest-args ${OESIGN_DIGEST_VALID_DEV_CONFIG_ARGS}
    --pkeyutl-args ${OESIGN_PKEYUTL_DEV_CONFIG_ARGS} --oesign-args
    ${OESIGN_SIGN_VALID_DEV_CONFIG_ARGS})

set_tests_properties(
  tests/oesign-digest-valid-dev-config-args
  PROPERTIES PASS_REGULAR_EXPRESSION "PASS: Launch of signed enclave succeeded")

# Test digest command missing --enclave-image (-e) argument
add_test(NAME tests/oesign-digest-missing-enclave-arg
         COMMAND oesign digest -c ${OESIGN_TEST_INPUTS_DIR}/valid.conf -d
                 oesign_test_enc.digest)

set_tests_properties(
  tests/oesign-digest-missing-enclave-arg
  PROPERTIES PASS_REGULAR_EXPRESSION "ERROR: --enclave-image option is missing")

# Test digest command missing --digest-file (-d) argument
add_test(NAME tests/oesign-digest-missing-digest-arg
         COMMAND oesign digest -e $<TARGET_FILE:oesign_test_enc> -c
                 ${OESIGN_TEST_INPUTS_DIR}/valid.conf)

set_tests_properties(
  tests/oesign-digest-missing-digest-arg
  PROPERTIES PASS_REGULAR_EXPRESSION "ERROR: --digest-file option is missing")

# Test sign command for digest options missing --enclave (-e) argument
add_test(
  NAME tests/oesign-digest-sign-missing-enclave-arg
  COMMAND
    oesign sign -c ${OESIGN_TEST_INPUTS_DIR}/valid.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-missing-enclave-arg
  PROPERTIES PASS_REGULAR_EXPRESSION "ERROR: --enclave-image option is missing")

# Test sign command for digest options missing --x509 (-x) argument
add_test(
  NAME tests/oesign-digest-sign-missing-x509-arg
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -d oesign_test_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-missing-x509-arg
  PROPERTIES PASS_REGULAR_EXPRESSION
             "ERROR: --digest-signature must be used with --x509")

# Test sign command for digest options missing --digest-file (-d) argument
add_test(
  NAME tests/oesign-digest-sign-missing-digest-sig-arg
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem)

set_tests_properties(
  tests/oesign-digest-sign-missing-digest-sig-arg
  PROPERTIES PASS_REGULAR_EXPRESSION
             "ERROR: --digest-signature must be used with --x509")

# Test sign command for digest options with conflicting --key-file (-k) argument
add_test(
  NAME tests/oesign-digest-sign-conflicting-key-file-arg
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_enc.baseline.digest.sig -k
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

set_tests_properties(
  tests/oesign-digest-sign-conflicting-key-file-arg
  PROPERTIES PASS_REGULAR_EXPRESSION
             "ERROR: --key-file cannot be used with digest signing options")

# Test sign command for digest options with mismatched public key
add_test(
  NAME tests/oesign-digest-sign-mismatched-x509
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key_2.cert.pem -d
    oesign_test_enc.baseline.digest.sig)

set(OESIGN_DIGEST_SIGN_MISMATCHED_X509_REGEX
    "ERROR: Digest signature cannot be validated against the specified enclave configuration using the provided certificate"
)
if (WIN32)
  # Windows occasionally returns STATUS_INVALID_PARAMETER (0xc000000d) instead, see issue #3132
  string(APPEND OESIGN_DIGEST_SIGN_MISMATCHED_X509_REGEX
         "\;BCryptVerifySignature failed \\(err=0xc000000d\\)")
endif ()

set_tests_properties(
  tests/oesign-digest-sign-mismatched-x509
  PROPERTIES PASS_REGULAR_EXPRESSION
             ${OESIGN_DIGEST_SIGN_MISMATCHED_X509_REGEX})

# Test sign command for digest options with mismatched Debug config
# Also validates that the config Debug value overwrites the build time one
add_test(
  NAME tests/oesign-digest-sign-new-debug-config
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_alt_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/non_debug.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_alt_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-new-debug-config
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: Digest signature cannot be validated against the specified enclave configuration using the provided certificate"
)

# Test sign command for digest options with mismatched NumHeapPages config
# Also validates that the config NumHeapPages value overwrites the build time one
add_test(
  NAME tests/oesign-digest-sign-new-num-heap-pages
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_alt_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/more_num_heap_pages.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_alt_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-new-num-heap-pages
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: Digest signature cannot be validated against the specified enclave configuration using the provided certificate"
)

# Test sign command for digest options with mismatched NumStackPages config
# Also validates that the config NumStackPages value overwrites the build time one
add_test(
  NAME tests/oesign-digest-sign-new-num-stack-pages
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_alt_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/more_num_stack_pages.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_alt_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-new-num-stack-pages
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: Digest signature cannot be validated against the specified enclave configuration using the provided certificate"
)

# Test sign command for digest options with mismatched NumTCS config
# Also validates that the config NumTCS value overwrites the build time one
add_test(
  NAME tests/oesign-digest-sign-new-num-tcs
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_alt_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/more_num_tcs.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_alt_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-new-num-tcs
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: Digest signature cannot be validated against the specified enclave configuration using the provided certificate"
)

# Test sign command for digest options with mismatched ProductID config
# Also validates that the config ProductID value overwrites the build time one
add_test(
  NAME tests/oesign-digest-sign-new-product-id
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_alt_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/new_product_id.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_alt_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-new-product-id
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: Digest signature cannot be validated against the specified enclave configuration using the provided certificate"
)

# Test sign command for digest options with mismatched SecurityVersion config
# Also validates that the config SecurityVersion value overwrites the build time one
add_test(
  NAME tests/oesign-digest-sign-new-security-version
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_alt_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/new_security_version.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_alt_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-new-security-version
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: Digest signature cannot be validated against the specified enclave configuration using the provided certificate"
)

# Test sign command for digest options with mismatched enclave MRENCLAVE
add_test(
  NAME tests/oesign-digest-sign-alt-enclave
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_alt_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -x
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.cert.pem -d
    oesign_test_enc.baseline.digest.sig)

set_tests_properties(
  tests/oesign-digest-sign-alt-enclave
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "ERROR: Digest signature cannot be validated against the specified enclave configuration using the provided certificate"
)
