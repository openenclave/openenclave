# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../helloworld.edl host gen)

add_executable(helloworld_host host.c ${gen})

target_include_directories(helloworld_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(helloworld_host oehostapp)

