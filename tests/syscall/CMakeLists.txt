# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if(UNIX)
add_subdirectory(cpio)
add_subdirectory(datagram)
add_subdirectory(dup)
add_subdirectory(epoll)
add_subdirectory(fs)
add_subdirectory(hostfs)
add_subdirectory(ids)
add_subdirectory(poller)
add_subdirectory(resolver)
add_subdirectory(socket)
add_subdirectory(socketpair)
add_subdirectory(sendmsg)
endif()
