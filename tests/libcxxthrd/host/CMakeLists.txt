# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libcxxthrd_host host.cpp)
target_compile_options(libcxxthrd_host PRIVATE --std=c++14)
target_link_libraries(libcxxthrd_host oehostapp)
