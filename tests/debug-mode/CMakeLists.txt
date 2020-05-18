# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
  add_enclave_test(tests/debug-unsigned debug_host debug_enc debug unsigned)
  set_enclave_tests_properties(tests/debug-unsigned PROPERTIES SKIP_RETURN_CODE
                               2)
endif ()

add_enclave_test(tests/debug-signed debug_host debug_enc_signed debug signed)
add_enclave_test(tests/nodebug-signed debug_host no_debug_enc_signed nodebug
                 signed)
add_enclave_test(tests/nodebug-unsigned debug_host no_debug_enc_unsigned
                 nodebug unsigned)

set_enclave_tests_properties(tests/debug-signed PROPERTIES SKIP_RETURN_CODE 2)
set_enclave_tests_properties(tests/nodebug-signed PROPERTIES SKIP_RETURN_CODE 2)
set_enclave_tests_properties(tests/nodebug-unsigned PROPERTIES SKIP_RETURN_CODE
                             2)
