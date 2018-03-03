# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(mbedhost host.c)
target_link_libraries(mbedhost oehostapp)
