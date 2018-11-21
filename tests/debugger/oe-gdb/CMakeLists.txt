# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(enc)

add_test(
    NAME oe-gdb-test
    COMMAND 
        ${OE_BINDIR}/oe-gdb --batch 
        --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb 
        -arg host/oe_gdb_test_host enc/oe_gdb_test_enc
)

add_test(
    NAME oe-gdb-test-simulation-mode
    COMMAND 
        ${OE_BINDIR}/oe-gdb --batch 
        --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb 
        -arg host/oe_gdb_test_host enc/oe_gdb_test_enc --simulation-mode
)
