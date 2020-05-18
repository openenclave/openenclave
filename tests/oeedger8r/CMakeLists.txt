# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/oeedger8r edl_host edl_enc)
add_enclave_test(tests/oeedger8r_other edl_host edl_other_enc)

add_custom_target(edl_gen DEPENDS edl_enc_gen edl_host_gen)

add_subdirectory(behavior)
