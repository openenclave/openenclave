# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/child_thread_ecall child_thread_host child_thread_enc 0)
add_enclave_test(tests/child_thread_destroy child_thread_host child_thread_enc
                 1)
#add_enclave_test(tests/child_thread_ecall_and_destroy child_thread_host child_thread_enc 2)
#add_enclave_test(tests/child_thread_ocall_and_destroy child_thread_host child_thread_enc 3)
