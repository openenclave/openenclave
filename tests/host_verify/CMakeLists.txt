# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_test(
  NAME tests/host_verify
  COMMAND $<TARGET_FILE:test_host_verify>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:test_host_verify>)

# The test binary will dump the "tcb_status" claims for TD relaunch quote
# Expected to see tcb_status: 07000000
#
# PASS_REGULAR_EXPRESSION makes CTest ignore the process exit code, so the
# expression must also require the marker that main() prints only after every
# check has run. Without it, an OE_TEST abort occurring after the TD relaunch
# quote is verified would still be reported as a pass.
set_tests_properties(
  tests/host_verify
  PROPERTIES PASS_REGULAR_EXPRESSION
             "tcb_status: 07000000(.|\n)*host_verify: all tests passed")
