# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(enc)

add_test(
    NAME oegdb-test
    COMMAND
        ${OE_BINDIR}/oegdb --batch
        --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb
        -arg host/oe_gdb_test_host enc/oe_gdb_test_enc
)

add_test(
    NAME oegdb-test-simulation-mode
    COMMAND
        ${OE_BINDIR}/oegdb --batch
        --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb
        -arg host/oe_gdb_test_host enc/oe_gdb_test_enc --simulation-mode
)
