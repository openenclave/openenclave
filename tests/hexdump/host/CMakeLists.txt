# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(hexdump_host host.c)
target_link_libraries(hexdump_host oehostapp)
