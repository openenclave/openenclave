# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../SampleApp.edl host gen)

add_executable(SampleAppHost SampleAppHost.cpp ${gen})

target_include_directories(SampleAppHost PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(SampleAppHost oehostapp)
