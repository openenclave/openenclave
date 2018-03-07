# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ocallhost host.cpp)

target_link_libraries(ocallhost oehostapp)

target_compile_options(ocallhost PRIVATE
    -Wno-error=unused-but-set-variable
    -Wno-error=unused-variable
    )
