# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(hostcallshost host.cpp)

target_link_libraries(hostcallshost oehostapp)
