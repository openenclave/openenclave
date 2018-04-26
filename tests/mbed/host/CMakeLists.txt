# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(mbed_host host.c)
target_link_libraries(mbed_host oehostapp)
