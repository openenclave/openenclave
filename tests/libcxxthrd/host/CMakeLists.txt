# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libcxxthrd_host host.cpp)

target_link_libraries(libcxxthrd_host oehostapp)
