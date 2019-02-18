# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(samples/helloworld helloworld_host helloworld_enc_signed)
set_tests_properties(samples/helloworld PROPERTIES SKIP_RETURN_CODE 1)
add_enclave_test(samples/helloworld_simulation helloworld_host helloworld_enc_signed --simulate)
