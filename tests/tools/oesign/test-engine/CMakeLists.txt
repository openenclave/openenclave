# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oesign_test_engine SHARED oesign-test-engine.c)

target_include_directories(oesign_test_engine PRIVATE include)

set(OESIGN_TEST_INPUTS_DIR ${CMAKE_CURRENT_BINARY_DIR}/../test-inputs)

# Sign enclave
add_custom_command(
  OUTPUT oesign_test_enc.engine_signed
  DEPENDS oesign_test_enc oesign_test_keys oesign_test_engine
  COMMAND cmake -E copy $<TARGET_FILE:oesign_test_enc>
          ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND
    oesign sign -e oesign_test_enc -c ${OESIGN_TEST_INPUTS_DIR}/valid.conf -n
    'oesign-test-engine' -p $<TARGET_FILE:oesign_test_engine> -i
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem
  COMMAND cmake -E rename oesign_test_enc.signed oesign_test_enc.engine_signed)

add_custom_target(oesign_engine_sign ALL DEPENDS oesign_test_enc.engine_signed)

add_test(NAME tests/oesign-engine-verify-signed
         COMMAND $<TARGET_FILE:oesign_test_host> oesign_test_enc.engine_signed)

add_test(
  NAME tests/oesign-engine-failed-engine-path
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:oesign_test_enc>
    --config-file ${OESIGN_TEST_INPUTS_DIR}/valid.conf --engine-id
    'oesign-test-engine' --engine-load-path '/tmp/no_there' --key-id
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-failed-engine-id
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:oesign_test_enc>
    --config-file ${OESIGN_TEST_INPUTS_DIR}/valid.conf --engine-id
    'oesign-test' --engine-load-path $<TARGET_FILE:oesign_test_engine> --key-id
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-failed-key-id
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:oesign_test_enc>
    --config-file ${OESIGN_TEST_INPUTS_DIR}/valid.conf --engine-id
    'oesign-test-engine' --engine-load-path $<TARGET_FILE:oesign_test_engine>
    --key-id 'bogus\ key' --expect-fail)

add_test(
  NAME tests/oesign-engine-works
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:oesign_test_enc>
    --config-file ${OESIGN_TEST_INPUTS_DIR}/valid.conf --engine-id
    'oesign-test-engine' --engine-load-path $<TARGET_FILE:oesign_test_engine>
    --key-id ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)

add_test(
  NAME tests/oesign-engine-sign-wrong
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:oesign_test_enc>
    --config-file ${OESIGN_TEST_INPUTS_DIR}/valid.conf --engine-id
    'oesign-test-engine' --engine-load-path $<TARGET_FILE:oesign_test_engine>
    --key-id ${OESIGN_TEST_INPUTS_DIR}/bad_exp_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-sign-config-negval
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:oesign_test_enc>
    --config-file ${OESIGN_TEST_INPUTS_DIR}/negative_num_heap_pages.conf
    --engine-id 'oesign-test-engine' --engine-load-path
    $<TARGET_FILE:oesign_test_engine> --key-id
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-sign-empty-config
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:oesign_test_enc>
    --config-file ${OESIGN_TEST_INPUTS_DIR}/empty.conf --engine-id
    'oesign-test-engine' --engine-load-path $<TARGET_FILE:oesign_test_engine>
    --key-id ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-sign
  COMMAND
    oesign sign -e $<TARGET_FILE:oesign_test_enc> -c
    ${OESIGN_TEST_INPUTS_DIR}/valid.conf -n oesign-test-engine -p
    $<TARGET_FILE:oesign_test_engine> -i
    ${OESIGN_TEST_INPUTS_DIR}/sign_key.private.pem)
