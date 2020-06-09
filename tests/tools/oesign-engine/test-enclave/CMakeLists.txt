# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(enclave)
add_subdirectory(host)

if (DEFINED ENV{OE_SIMULATION})
  set(SIMULATION ON)
else ()
  set(SIMULATION OFF)
endif ()

# Generate an empty config file
add_custom_command(OUTPUT empty.conf
                   COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py 0)

# Generate a config file with negative value
add_custom_command(OUTPUT negative_num_heap_pages.conf
                   COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py 1)

add_custom_target(oesign_test_configs ALL DEPENDS empty.conf
                                                  negative_num_heap_pages.conf)

# Generate a valid SGX signing key-pair
add_custom_command(
  OUTPUT sign_key.private.pem sign_key.public.pem
  COMMAND openssl genrsa -out sign_key.private.pem -3 3072
  COMMAND openssl rsa -in sign_key.private.pem -pubout -out sign_key.public.pem)

# Generate an RSA key-pair with invalid exponent for SGX signing
add_custom_command(
  OUTPUT bad_exp_key.private.pem bad_exp_key.public.pem
  COMMAND openssl genrsa -out bad_exp_key.private.pem 3072
  COMMAND openssl rsa -in bad_exp_key.private.pem -pubout -out
          bad_exp_key.public.pem)

add_custom_target(
  oesgin_test_keys ALL DEPENDS sign_key.private.pem sign_key.public.pem
                               bad_exp_key.private.pem bad_exp_key.public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/test-enclave.conf sign_key.private.pem ../test-engine
  COMMAND
    oesign sign -e $<TARGET_FILE:enclave> -c
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf -n
    'oesign-test-engine' -p
    ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so -i
    ${CMAKE_CURRENT_BINARY_DIR}/sign_key.private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)

if (SIMULATION)
  add_custom_target(
    run
    DEPENDS test-enclave_host sign oesign test-enclave-engine
    COMMAND test-enclave_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS test-enclave_host ../test-engine sign oesign
  COMMAND test-enclave_host ${CMAKE_CURRENT_BINARY_DIR}/enclave/enclave.signed
          --simulate)

add_test(
  NAME tests/oesign-engine-failed-engine-path
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:enclave> --config-file
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf --engine-id
    'oesign-test-engine' --engine-load-path '/tmp/no_there' --key-id
    ${CMAKE_CURRENT_BINARY_DIR}/sign_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-failed-engine-id
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:enclave> --config-file
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf --engine-id
    'oesign-test' --engine-load-path
    ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
    --key-id ${CMAKE_CURRENT_BINARY_DIR}/sign_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-failed-key-id
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:enclave> --config-file
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf --engine-id
    'oesign-test-engine' --engine-load-path
    ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
    --key-id 'bogus\ key' --expect-fail)

add_test(
  NAME tests/oesign-engine-works
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:enclave> --config-file
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf --engine-id
    'oesign-test-engine' --engine-load-path
    ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
    --key-id ${CMAKE_CURRENT_BINARY_DIR}/sign_key.private.pem)

add_test(
  NAME tests/oesign-engine-sign-wrong
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:enclave> --config-file
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf --engine-id
    'oesign-test-engine' --engine-load-path
    ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
    --key-id ${CMAKE_CURRENT_BINARY_DIR}/bad_exp_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-sign-config-negval
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:enclave> --config-file
    ${CMAKE_CURRENT_BINARY_DIR}/negative_num_heap_pages.conf --engine-id
    'oesign-test-engine' --engine-load-path
    ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
    --key-id ${CMAKE_CURRENT_BINARY_DIR}/sign_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-sign-empty-config
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py --oesign-binary
    ${OE_BINDIR}/oesign --enclave-binary $<TARGET_FILE:enclave> --config-file
    ${CMAKE_CURRENT_BINARY_DIR}/empty.conf --engine-id 'oesign-test-engine'
    --engine-load-path
    ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
    --key-id ${CMAKE_CURRENT_BINARY_DIR}/sign_key.private.pem --expect-fail)

add_test(
  NAME tests/oesign-engine-sign
  COMMAND
    oesign sign -e $<TARGET_FILE:enclave> -c
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf -n oesign-test-engine
    -p ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so -i
    ${CMAKE_CURRENT_BINARY_DIR}/sign_key.private.pem)

add_test(NAME tests/oesign-engine-sign-runnable COMMAND host/helloworld_host
                                                        enclave/enclave.signed)

add_test(
  NAME tests/oesign-engine-sign-kss
  COMMAND
    oesign sign -e $<TARGET_FILE:enclave> -c
    ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave-kss.conf -n oesign-test-engine
    -p ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so -i
    ${CMAKE_CURRENT_BINARY_DIR}/sign_key.private.pem)
