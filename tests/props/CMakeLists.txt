# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)

  # Test unsigned enclave:
  add_enclave_test(tests/props_unsigned props_host props_enc_unsigned unsigned)
endif ()

# Test a signed enclave:
add_enclave_test(tests/props props_host props_enc_signed signed)
