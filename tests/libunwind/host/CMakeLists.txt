# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libunwind_host host.cpp)

target_link_libraries(libunwind_host oehostapp)
