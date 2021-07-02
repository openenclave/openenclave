# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# stress test case definition:
# For create enclave & do ecall:
#   add_enclave_test(tests/your_stress_test_name stress_host stress_enc stress_test_type enclave_count do_ecall_count)
# For memory management:
#   add_enclave_test(tests/your_stress_test_name stress_host stress_enc stress_test_type do_memory_count memory_size)
# For multi-thread:
#   add_enclave_test(tests/your_stress_test_name stress_host stress_enc stress_test_type thread_count enclave_count)

# stress_test_type:
# - ECALL_STRESS_TEST
# - OCALL_STRESS_TEST
# - MEMORY_MANAGEMENT_STRESS_TEST
# - MULTITHREAD_STRESS_TEST
set(ECALL_STRESS_TEST 0)
set(OCALL_STRESS_TEST 1)
set(MEMORY_MANAGEMENT_STRESS_TEST 2)
set(MULTITHREAD_STRESS_TEST 3)

add_enclave_test(tests/stress_ecall_1 stress_host stress_enc
                 ${ECALL_STRESS_TEST} 1 10000)
add_enclave_test(tests/stress_ecall_2 stress_host stress_enc
                 ${ECALL_STRESS_TEST} 10 1000)
add_enclave_test(tests/stress_memory_management_1 stress_host stress_enc
                 ${MEMORY_MANAGEMENT_STRESS_TEST} 10000 4096)
add_enclave_test(tests/stress_multithread_1 stress_host stress_enc
                 ${MULTITHREAD_STRESS_TEST} 10 10)

if (ENABLE_FULL_STRESS_TESTS)
  add_enclave_test(tests/stress_ecall_3 stress_host stress_enc
                   ${ECALL_STRESS_TEST} 1 1000000)
  add_enclave_test(tests/stress_ecall_4 stress_host stress_enc
                   ${ECALL_STRESS_TEST} 100 10000)
  add_enclave_test(tests/stress_memory_management_2 stress_host stress_enc
                   ${MEMORY_MANAGEMENT_STRESS_TEST} 1000000 32768)
  add_enclave_test(tests/stress_multithread_2 stress_host stress_enc
                   ${MULTITHREAD_STRESS_TEST} 100 100)
endif ()
