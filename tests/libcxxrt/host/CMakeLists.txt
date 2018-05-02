# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libcxxrthost host.cpp)

target_link_libraries(libcxxrthost oehostapp)
