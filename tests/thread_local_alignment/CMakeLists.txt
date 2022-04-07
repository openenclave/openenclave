# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# Use add_enclave_test to ensure the enclave binaries are copied from the pre-built directory
# when ADD_WINDOWS_ENCLAVE_TESTS is ON and BUILD_ENCLAVES is OFF.
add_enclave_test(tests/thread_local_alignment alignment_host alignment_enc_16_8)

add_test(
  NAME thread_local_alignment_1x
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND host/alignment_host enc/alignment_enc_1_8 enc/alignment_enc_1_16
          enc/alignment_enc_1_32 enc/alignment_enc_1_64 enc/alignment_enc_1_128)

add_test(
  NAME thread_local_alignment_2x
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND host/alignment_host enc/alignment_enc_2_8 enc/alignment_enc_2_16
          enc/alignment_enc_2_32 enc/alignment_enc_2_64 enc/alignment_enc_2_128)

add_test(
  NAME thread_local_alignment_4x
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND host/alignment_host enc/alignment_enc_4_8 enc/alignment_enc_4_16
          enc/alignment_enc_4_32 enc/alignment_enc_4_64 enc/alignment_enc_4_128)

add_test(
  NAME thread_local_alignment_8x
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND host/alignment_host enc/alignment_enc_8_8 enc/alignment_enc_8_16
          enc/alignment_enc_8_32 enc/alignment_enc_8_64 enc/alignment_enc_8_128)

add_test(
  NAME thread_local_alignment_16x
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND
    host/alignment_host enc/alignment_enc_16_8 enc/alignment_enc_16_16
    enc/alignment_enc_16_32 enc/alignment_enc_16_64 enc/alignment_enc_16_128)

add_test(
  NAME thread_local_alignment_32x
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND
    host/alignment_host enc/alignment_enc_32_8 enc/alignment_enc_32_16
    enc/alignment_enc_32_32 enc/alignment_enc_32_64 enc/alignment_enc_32_128)

add_test(
  NAME thread_local_alignment_64x
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND
    host/alignment_host enc/alignment_enc_64_8 enc/alignment_enc_64_16
    enc/alignment_enc_64_32 enc/alignment_enc_64_64 enc/alignment_enc_64_128)

add_test(
  NAME thread_local_alignment_128x
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND
    host/alignment_host enc/alignment_enc_128_8 enc/alignment_enc_128_16
    enc/alignment_enc_128_32 enc/alignment_enc_128_64 enc/alignment_enc_128_128)
