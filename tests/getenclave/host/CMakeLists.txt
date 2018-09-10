# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(getenclave_host host.c)

target_link_libraries(getenclave_host oehostapp)
