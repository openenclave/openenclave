# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libmbedtesthost host.c ocalls.c)

target_compile_options(libmbedtesthost PRIVATE
     -Wno-error
    )

target_link_libraries(libmbedtesthost oehostapp)
