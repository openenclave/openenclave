# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../typeinfo.edl host gen)

add_executable(typeinfo_host host.c ${gen})

target_include_directories(typeinfo_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(typeinfo_host oehostapp)
