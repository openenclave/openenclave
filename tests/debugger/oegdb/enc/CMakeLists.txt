# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../oe_gdb_test.edl enclave oe_gdb_test_t)

add_enclave(TARGET oe_gdb_test_enc SOURCES enc.c contract.c ${oe_gdb_test_t})

target_include_directories(oe_gdb_test_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(oe_gdb_test_enc oelibc)
