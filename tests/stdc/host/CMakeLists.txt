# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../stdc.edl host gen)

add_executable(stdc_host host.cpp ${gen})

target_include_directories(stdc_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(stdc_host oehostapp)
