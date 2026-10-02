# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_subdirectory(host)

# Bypass the test when ADD_WINDOWS_ENCLAVE_TESTS given that the test does not
# follow the "HOST ENCLAVE ARGS" pattern.
if (NOT ADD_WINDOWS_ENCLAVE_TESTS)
  add_test(
    NAME tests/oeseal
    COMMAND
      ${CMAKE_COMMAND} -E env bash -c
      "echo 123456789 > testfile &&\
       host/oeseal seal -e enc/sgx_oeseal_enc -i testfile -o test_seal -v &&\
       host/oeseal unseal -e enc/sgx_oeseal_enc -i test_seal -o test_unseal -v &&\
       cmp -n 9 testfile test_unseal")

  set_tests_properties(tests/oeseal PROPERTIES SKIP_RETURN_CODE 2)
endif ()
