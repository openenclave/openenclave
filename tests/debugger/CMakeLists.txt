# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (NOT UNIX OR BUILD_TYPE_UPPER STREQUAL "RELEASE")
  return()
endif ()

add_subdirectory(non_debug)
add_subdirectory(host)
add_subdirectory(enc)

add_test(
  NAME oegdb-test
  COMMAND
    ${OE_BINDIR}/oegdb --batch -nh # Do not use user's gdbinit
    --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb
    --return-child-result # This fails the test in case of any error.
    -arg host/db_test_host enc/db_test_enc)

add_test(
  NAME oegdb-test-simulation-mode
  COMMAND
    ${OE_BINDIR}/oegdb --batch -nh # Do not use user's gdbinit
    --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb
    --return-child-result # This fails the test in case of any error.
    -arg host/db_test_host enc/db_test_enc --simulation-mode)

if (CODE_COVERAGE)
  add_test(
    NAME oelldb-test
    COMMAND
      ${OE_BINDIR}/oelldb -o
      "command script import ${CMAKE_CURRENT_SOURCE_DIR}/commands.py" -o "quit"
      -- host/db_test_host enc/db_test_enc)

  set_tests_properties(oelldb-test PROPERTIES PASS_REGULAR_EXPRESSION
                                              "oelldb test passed")
  add_test(
    NAME oelldb-test-simulation-mode
    COMMAND
      ${OE_BINDIR}/oelldb -o
      "command script import ${CMAKE_CURRENT_SOURCE_DIR}/commands.py" -o "quit"
      -- host/db_test_host enc/db_test_enc --simulation-mode)

  set_tests_properties(oelldb-test-simulation-mode
                       PROPERTIES PASS_REGULAR_EXPRESSION "oelldb test passed")
endif ()
