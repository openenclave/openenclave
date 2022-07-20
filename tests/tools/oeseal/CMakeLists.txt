# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_subdirectory(host)

add_test(
  NAME tests/oeseal
  COMMAND
    ${CMAKE_COMMAND} -E env bash -c
    "host/oeseal seal -e enc/sgx_oeseal_enc -i ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt -o test_seal -v &&\
     host/oeseal unseal -e enc/sgx_oeseal_enc -i test_seal -o test_unseal -v &&\
     cmp -n 4096 ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt test_unseal")

set_tests_properties(tests/oeseal PROPERTIES SKIP_RETURN_CODE 2)
