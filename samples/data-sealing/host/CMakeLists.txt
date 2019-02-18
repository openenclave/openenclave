# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../datasealing.edl host gen)

add_executable(data-sealing_host host.cpp ${gen})

target_include_directories(data-sealing_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(data-sealing_host oehostapp)

