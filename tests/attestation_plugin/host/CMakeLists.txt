# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../plugin.edl host gen)

add_executable(plugin_host host.c ../plugin/tests.c ${gen})

target_include_directories(plugin_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(plugin_host oehostapp)