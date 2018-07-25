# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(create_rapid_host host.cpp)

target_compile_options(create_rapid_host PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>
    )

target_link_libraries(create_rapid_host oehostapp)
