# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../poller.edl host gen)

add_executable(poller_host host.cpp ../client.cpp ../server.cpp ${gen})

target_include_directories(poller_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(poller_host oehostapp)
