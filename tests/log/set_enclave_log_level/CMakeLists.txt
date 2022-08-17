# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/set_enclave_log_level set_enclave_log_level_host
                 set_enclave_log_level_enc)

set_enclave_tests_properties(
  tests/set_enclave_log_level
  PROPERTIES
  PASS_REGULAR_EXPRESSION
  "Enclave] host_log_level=INFO, message log_level=INFO.+Enclave] host_log_level=INFO, message log_level=WARN.+Enclave] host_log_level=INFO, message log_level=ERROR.+Enclave] host_log_level=WARN, message log_level=WARN.+Enclave] host_log_level=WARN, message log_level=ERROR.+Enclave] host_log_level=ERROR, message log_level=ERROR"
)
