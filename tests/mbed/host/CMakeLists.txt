# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libmbedtest_host host.c)

target_compile_options(libmbedtest_host PRIVATE -Wno-error)

target_link_libraries(libmbedtest_host oehostapp)
