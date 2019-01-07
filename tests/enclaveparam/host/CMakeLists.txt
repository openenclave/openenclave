# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../enclaveparam.edl host gen)

add_executable(enclaveparam_host host.c ${gen})

target_include_directories(enclaveparam_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclaveparam_host oehostapp)
