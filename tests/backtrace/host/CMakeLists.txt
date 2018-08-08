# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(backtrace_host host.cpp)
target_link_libraries(backtrace_host oehostapp)
