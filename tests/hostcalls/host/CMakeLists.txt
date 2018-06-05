# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(hostcalls_host host.cpp)

target_link_libraries(hostcalls_host oehostapp)
