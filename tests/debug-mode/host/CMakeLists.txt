# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(debug_host host.c)

target_link_libraries(debug_host oehostapp)
