# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(enc1)
  add_subdirectory(enc2)
endif ()
add_subdirectory(host)

add_enclave_test(tests/ecall_conflict ecall_conflict_host ecall_conflict_enc1
                 enc/ecall_conflict_enc2)
