# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(bigmalloc_host host.c)

target_link_libraries(bigmalloc_host oehostapp)
