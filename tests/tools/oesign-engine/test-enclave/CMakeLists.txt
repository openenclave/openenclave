# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("oesign-test" LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(enclave)
add_subdirectory(host)

if (DEFINED ENV{OE_SIMULATION})
    set(SIMULATION ON)
else()
    set(SIMULATION OFF)
endif()

# Generate key
add_custom_command(OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# wrong key for testing
add_custom_command(OUTPUT wrongprivate.pem wrongpublic.pem
  COMMAND openssl genrsa -out wrongprivate.pem  3072
  COMMAND openssl rsa -in wrongprivate.pem -pubout -out wrongpublic.pem)

# Sign enclave
add_custom_command(OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/test-enclave.conf private.pem ../test-engine
  COMMAND oesign sign -e $<TARGET_FILE:enclave> -c ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf -n 'oesign-test-engine' -p ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so -i ${CMAKE_CURRENT_BINARY_DIR}/private.pem )

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)

if (SIMULATION)
  add_custom_target(run
    DEPENDS test-enclave_host sign oesign test-enclave-engine
    COMMAND test-enclave_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(simulate
  DEPENDS test-enclave_host ../test-engine sign oesign
  COMMAND test-enclave_host ${CMAKE_CURRENT_BINARY_DIR}/enclave/enclave.signed --simulate)

add_test(NAME tests/oesign-engine-failed-engine-path
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py
                  --oesign-binary ${OE_BINDIR}/oesign
                  --enclave-binary $<TARGET_FILE:enclave>
                  --config-file ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf
                  --engine-id 'oesign-test-engine'
                  --engine-load-path '/tmp/no_there'
                  --key-id ${CMAKE_CURRENT_BINARY_DIR}/private.pem
                  --expect-fail )

add_test(NAME tests/oesign-engine-failed-engine-id
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py
                  --oesign-binary ${OE_BINDIR}/oesign
                  --enclave-binary $<TARGET_FILE:enclave>
                  --config-file ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf
                  --engine-id 'oesign-test'
                  --engine-load-path ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
                  --key-id ${CMAKE_CURRENT_BINARY_DIR}/private.pem
                  --expect-fail )

add_test(NAME tests/oesign-engine-failed-key-id
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py
                  --oesign-binary ${OE_BINDIR}/oesign
                  --enclave-binary $<TARGET_FILE:enclave>
                  --config-file ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf
                  --engine-id 'oesign-test-engine'
                  --engine-load-path ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
                  --key-id 'bogus\ key'
                  --expect-fail )

add_test(NAME tests/oesign-engine-works
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py
                  --oesign-binary ${OE_BINDIR}/oesign
                  --enclave-binary $<TARGET_FILE:enclave>
                  --config-file ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf
                  --engine-id 'oesign-test-engine'
                  --engine-load-path ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
                  --key-id ${CMAKE_CURRENT_BINARY_DIR}/private.pem )

add_test(NAME tests/oesign-engine-sign-wrong
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/oesign-test.py
                  --oesign-binary ${OE_BINDIR}/oesign
                  --enclave-binary $<TARGET_FILE:enclave>
                  --config-file ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf
                  --engine-id 'oesign-test-engine'
                  --engine-load-path ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so
                  --key-id ${CMAKE_CURRENT_BINARY_DIR}/wrongprivate.pem
                  --expect-fail )

add_test(NAME tests/oesign-engine-sign
         COMMAND oesign sign -e $<TARGET_FILE:enclave> -c ${CMAKE_CURRENT_SOURCE_DIR}/enclave/test-enclave.conf -n oesign-test-engine -p ${CMAKE_CURRENT_BINARY_DIR}/../test-engine/liboesign-test-engine.so -i ${CMAKE_CURRENT_BINARY_DIR}/private.pem )

add_test(NAME tests/oesign-engine-sign-runnable
         COMMAND host/helloworld_host enclave/enclave.signed)
set_tests_properties(tests/oesign-engine-sign-runnable PROPERTIES SKIP_RETURN_CODE 2)
