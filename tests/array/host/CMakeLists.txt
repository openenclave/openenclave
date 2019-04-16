# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../array.edl host gen)

add_executable(array_host host.c ${gen})

target_include_directories(array_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(array_host oehostapp)
