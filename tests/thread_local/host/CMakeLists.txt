# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../thread_local.edl host gen)

add_executable(thread_local_host host.cpp ${gen})

target_include_directories(thread_local_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(thread_local_host PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>
    )
target_link_libraries(thread_local_host oehostapp)
