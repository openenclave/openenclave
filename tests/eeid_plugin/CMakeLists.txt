# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/eeid_plugin eeid_plugin_host eeid_plugin_enc_signed
                 dynamic)
set_tests_properties(tests/eeid_plugin PROPERTIES SKIP_RETURN_CODE 2)

add_enclave_test(tests/eeid_plugin_static eeid_plugin_host
                 eeid_plugin_enc_static_signed static)
set_tests_properties(tests/eeid_plugin_static PROPERTIES SKIP_RETURN_CODE 2)
