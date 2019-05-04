# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This builds a library needed by later tests and must be first.
add_subdirectory(hostfs)

if (UNIX)
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
add_subdirectory(socket)
endif()
