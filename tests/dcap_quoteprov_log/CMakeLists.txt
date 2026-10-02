# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/dcap_quoteprov_log dcap_quoteprov_log_host
                 dcap_quoteprov_log_enc)

set_enclave_tests_properties(tests/dcap_quoteprov_log PROPERTIES
                             PASS_REGULAR_EXPRESSION "dcap_quoteprov\:")
