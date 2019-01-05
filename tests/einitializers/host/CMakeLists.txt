# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../test.edl host gen)

add_executable(einitializers_host host.c ${gen})

target_include_directories(einitializers_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(einitializers_host oehostapp)
