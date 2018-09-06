# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(memory_host host.cpp)

target_compile_options(memory_host PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>
    )

target_link_libraries(memory_host oehostapp)
