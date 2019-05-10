# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mintcb.edl host gen)

add_executable(mintcb_host host.c ${gen})

target_include_directories(mintcb_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(mintcb_host oehostapp)
