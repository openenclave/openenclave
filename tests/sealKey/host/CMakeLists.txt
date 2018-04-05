# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(sealKeyHost host.cpp)

target_compile_options(sealKeyHost PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    )

target_link_libraries(sealKeyHost oehostapp)
