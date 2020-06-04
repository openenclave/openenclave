# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/stress_ecall_1 stress_host stress_enc 0 1 1000000)

if (ENABLE_FULL_STRESS_TESTS)
  add_enclave_test(tests/stress_ecall_2 stress_host stress_enc 0 100 100000)
endif()
