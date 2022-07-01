# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_test(
  NAME oegdb-non-debug-enclave-test
  COMMAND
    ${OE_BINDIR}/oegdb --batch -nh # Do not use user's gdbinit
    --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb
    --return-child-result # This fails the test in case of any error.
    -arg host/non_debug_host enc/non_debug_enc --simulation-mode)

set_tests_properties(
  oegdb-non-debug-enclave-test
  PROPERTIES PASS_REGULAR_EXPRESSION "The enclave is not debuggable"
             FAIL_REGULAR_EXPRESSION "This should not be hit")

add_test(
  NAME oelldb-test
  COMMAND
    ${OE_BINDIR}/oelldb -o
    "command script import ${CMAKE_CURRENT_SOURCE_DIR}/commands.py" -o "quit"
    -- host/non_debug_host enc/non_debug_enc --simulation-mode)

set_tests_properties(
  oelldb-test
  PROPERTIES PASS_REGULAR_EXPRESSION "The enclave is not debuggable"
             FAIL_REGULAR_EXPRESSION "This should not be hit")
