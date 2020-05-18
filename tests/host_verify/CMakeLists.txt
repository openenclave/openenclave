# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_test(
  NAME tests/host_verify
  COMMAND $<TARGET_FILE:test_host_verify>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:test_host_verify>)
