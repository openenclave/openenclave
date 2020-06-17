# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# stress test case definition:
# add_enclave_test(tests/your_stress_test_name stress_host stress_enc stress_test_type enclave_count operation_count)

# stress_test_type:
# - ECALL_STRESS_TEST
# - OCALL_STRESS_TEST
# - ECALL_OCALL_STRESS_TEST
set(ECALL_STRESS_TEST 0)
set(OCALL_STRESS_TEST 1)
set(ECALL_OCALL_STRESS_TEST 2)

add_enclave_test(tests/stress_ecall_1 stress_host stress_enc ${ECALL_STRESS_TEST} 1 10000)
add_enclave_test(tests/stress_ecall_2 stress_host stress_enc ${ECALL_STRESS_TEST} 10 100)

if (ENABLE_FULL_STRESS_TESTS)
  add_enclave_test(tests/stress_ecall_3 stress_host stress_enc ${ECALL_STRESS_TEST} 1 1000000)
  add_enclave_test(tests/stress_ecall_4 stress_host stress_enc ${ECALL_STRESS_TEST} 100 10000)
endif()
