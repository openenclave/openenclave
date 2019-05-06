# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(hostfs)
add_subdirectory(socket)

if(UNIX)
add_subdirectory(cpio)
add_subdirectory(echod)
add_subdirectory(fs)
add_subdirectory(ids)
add_subdirectory(polling)
add_subdirectory(resolver)
add_subdirectory(sgxfs)
add_subdirectory(send)
add_subdirectory(sendmsg)
add_subdirectory(signal)
endif()
