# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../oe_gdb_test.edl host oe_gdb_test_u)

add_executable(oe_gdb_test_host 
    host.c 
    ${oe_gdb_test_u}
)

target_include_directories(oe_gdb_test_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(oe_gdb_test_host oehostapp)
