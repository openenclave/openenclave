# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(threadcxx_host host.cpp)
target_compile_options(threadcxx_host PRIVATE
    --std=c++11)
target_link_libraries(threadcxx_host oehostapp)
