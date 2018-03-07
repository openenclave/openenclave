# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libcxxhost host.cpp)

target_link_libraries(libcxxhost oehostapp)
