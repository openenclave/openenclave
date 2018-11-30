# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(thread_host host.cpp rwlocks_test_host.cpp)
target_compile_options(thread_host PRIVATE
    -Wconversion
    -Wpointer-arith
    --std=c++11)
target_link_libraries(thread_host oehostapp)
