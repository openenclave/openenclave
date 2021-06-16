# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/child_process_ecall child_process_host child_process_enc
                 0)
set_enclave_tests_properties(tests/child_process_ecall PROPERTIES
                             SKIP_RETURN_CODE 2)

# related issue #3099
add_enclave_test(tests/child_process_destroy child_process_host
                 child_process_enc 1)
set_enclave_tests_properties(tests/child_process_destroy PROPERTIES
                             SKIP_RETURN_CODE 2)

add_enclave_test(tests/child_process_create child_process_host
                 child_process_enc 2)
set_enclave_tests_properties(tests/child_process_create PROPERTIES
                             SKIP_RETURN_CODE 2)

add_enclave_test(tests/child_process_create_more child_process_host
                 child_process_enc 3)
set_enclave_tests_properties(tests/child_process_create_more PROPERTIES
                             SKIP_RETURN_CODE 2)
