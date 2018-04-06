# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(hexdumphost host.c)
target_link_libraries(hexdumphost oehostapp)
