# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(cryptohost host.c)
target_link_libraries(cryptohost oehostapp)
