# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/stack_smashing_protector ssp_host ssp_enc)
set_enclave_tests_properties(tests/stack_smashing_protector PROPERTIES
                             SKIP_RETURN_CODE 2)
