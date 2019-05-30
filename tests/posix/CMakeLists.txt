# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(cpio)
add_subdirectory(dup)
add_subdirectory(fs)
add_subdirectory(hostfs)
add_subdirectory(ids)
add_subdirectory(polling)
add_subdirectory(resolver)
add_subdirectory(socket)
add_subdirectory(socketpair)
add_subdirectory(send)
add_subdirectory(sendmsg)

if(UNIX)
add_subdirectory(echod)
add_subdirectory(sgxfs)
add_subdirectory(poller)
endif()
