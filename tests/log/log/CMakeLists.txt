# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/log log_host log_enc)

set_enclave_tests_properties(tests/log PROPERTIES PASS_REGULAR_EXPRESSION
                             "log from enclave.+log from host")
