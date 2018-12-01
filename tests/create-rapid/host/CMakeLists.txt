# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../create_rapid.edl host gen)

add_executable(create_rapid_host host.cpp ${gen})

target_compile_options(create_rapid_host PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

target_include_directories(create_rapid_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(create_rapid_host oehostapp)
