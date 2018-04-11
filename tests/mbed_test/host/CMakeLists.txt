# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libmbedtesthost host.cpp)

target_link_libraries(libmbedtesthost oehostapp)
