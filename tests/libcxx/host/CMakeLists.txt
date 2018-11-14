# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libcxx_host host.cpp)
target_compile_options(libcxx_host PRIVATE  -Wconversion -Wpointer-arith -std=c++14)
target_link_libraries(libcxx_host oehostapp)
