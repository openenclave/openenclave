# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../props.edl host gen)

add_executable(props_host host.c ${gen})

target_include_directories(props_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(props_host oehostapp)
target_compile_options(props_host PRIVATE -Wconversion -Wpointer-arith)
