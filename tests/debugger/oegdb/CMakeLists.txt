# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(enc)

add_test(
  NAME oegdb-test
  COMMAND
    ${OE_BINDIR}/oegdb --batch -nh # Do not use user's gdbinit
    --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb
    --return-child-result # This fails the test in case of any error.
    -arg host/oe_gdb_test_host enc/oe_gdb_test_enc)

add_test(
  NAME oegdb-test-simulation-mode
  COMMAND
    ${OE_BINDIR}/oegdb --batch -nh # Do not use user's gdbinit
    --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb
    --return-child-result # This fails the test in case of any error.
    -arg host/oe_gdb_test_host enc/oe_gdb_test_enc --simulation-mode)
