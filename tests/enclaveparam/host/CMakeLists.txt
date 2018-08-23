# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(enclaveparam_host host.c)

target_link_libraries(enclaveparam_host oehostapp)
