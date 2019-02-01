# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../VectorException.edl host gen)

add_executable(VectorException_host host.c ${gen})

target_link_libraries(VectorException_host oehostapp)

target_include_directories(VectorException_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})
