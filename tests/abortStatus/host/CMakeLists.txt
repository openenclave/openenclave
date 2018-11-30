# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(abortStatus_host host.cpp)

target_compile_options(abortStatus_host PRIVATE
    -Wconversion
    -Wpointer-arith
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    )

target_link_libraries(abortStatus_host oehostapp)
