# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/child_process_ecall child_process_host child_process_enc
                 0)

# Disabling until #3099 is addressed.
#add_enclave_test(tests/child_process_destroy child_process_host
#                 child_process_enc 1)

add_enclave_test(tests/child_process_create child_process_host
                 child_process_enc 2)
