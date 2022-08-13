# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc_a)
  add_subdirectory(enc_b)
endif ()

add_test(NAME tests/set_log_level_a
         COMMAND ${CMAKE_CURRENT_BINARY_DIR}/host/set_log_level_host
                 ${CMAKE_CURRENT_BINARY_DIR}/enc_a/set_log_level_a_enc)

add_test(NAME tests/set_log_level_b
         COMMAND ${CMAKE_CURRENT_BINARY_DIR}/host/set_log_level_host
                 ${CMAKE_CURRENT_BINARY_DIR}/enc_b/set_log_level_b_enc)

set_tests_properties(
  tests/set_log_level_a
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "Host log_level=INFO, message log_level=INFO.+Host log_level=INFO, message log_level=WARN.+Host log_level=INFO, message log_level=ERROR.+Host log_level=WARN, message log_level=WARN.+Host log_level=WARN, message log_level=ERROR.+Host log_level=ERROR, message log_level=ERROR.+Enclave log_level=WARN, message log_level=WARN.+Enclave log_level=WARN, message log_level=ERROR.+Enclave log_level=INFO, message log_level=INFO.+Enclave log_level=INFO, message log_level=WARN.+Enclave log_level=INFO, message log_level=ERROR.+Enclave log_level=ERROR, message log_level=ERROR"
)

set_tests_properties(
  tests/set_log_level_a
  PROPERTIES
    FAIL_REGULAR_EXPRESSION
    "Host log_level=ERROR, message log_level=INFO;Host log_level=ERROR, message log_level=WARN;Host log_level=WARN, message log_level=INFO;Enclave log_level=ERROR, message log_level=INFO;Enclave log_level=ERROR, message log_level=WARN;Enclave log_level=WARN, message log_level=INFO"
)
