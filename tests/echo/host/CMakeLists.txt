# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../echo.edl host gen)

add_executable(echo_host host.c ${gen})

target_include_directories(echo_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(echo_host oehostapp)
