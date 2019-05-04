# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(hostfs)
add_subdirectory(eventfd)
add_subdirectory(hostepoll)
add_subdirectory(hostresolver)
add_subdirectory(hostsock)

if(UNIX)
add_subdirectory(sgxfs)
endif()
