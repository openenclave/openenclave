# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../memory.edl host gen)

add_executable(memory_host host.cpp ${gen})

target_include_directories(memory_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(memory_host oehostapp)
