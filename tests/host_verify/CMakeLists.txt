# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_test(
  NAME tests/host_verify
  COMMAND $<TARGET_FILE:test_host_verify>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:test_host_verify>)

# The test binary will dump the "tcb_status" claims for TD relaunch quote
# Expected to see tcb_status: 07000000
set_tests_properties(tests/host_verify PROPERTIES PASS_REGULAR_EXPRESSION
                                                  "tcb_status: 07000000")
