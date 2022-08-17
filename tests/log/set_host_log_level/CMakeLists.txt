# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/set_host_log_level set_host_log_level_host
                 set_host_log_level_enc)

set_enclave_tests_properties(
  tests/set_host_log_level
  PROPERTIES
  PASS_REGULAR_EXPRESSION
  "Host] log_level=INFO, message log_level=INFO.+Host] log_level=INFO, message log_level=WARN.+Host] log_level=INFO, message log_level=ERROR.+Host] log_level=WARN, message log_level=WARN.+Host] log_level=WARN, message log_level=ERROR.+Host] log_level=ERROR, message log_level=ERROR"
)

set_enclave_tests_properties(
  tests/set_host_log_level
  PROPERTIES
  PASS_REGULAR_EXPRESSION
  "Host] log_level=INFO, message log_level=INFO.+Host] log_level=INFO, message log_level=WARN.+Host] log_level=INFO, message log_level=ERROR.+Enclave] host_log_level=INFO, message log_level=ERROR.+Host] log_level=WARN, message log_level=WARN.+Host] log_level=WARN, message log_level=ERROR.+Enclave] host_log_level=WARN, message log_level=ERROR.+Host] log_level=ERROR, message log_level=ERROR.+Enclave] host_log_level=ERROR, message log_level=ERROR"
)
