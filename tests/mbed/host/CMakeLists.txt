# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(libmbedtest_host host.cpp)

target_link_libraries(libmbedtest_host oehostapp)
