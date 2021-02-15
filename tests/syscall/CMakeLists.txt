# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(cpio)
add_subdirectory(resolver)
add_subdirectory(socket)
add_subdirectory(tool)

# Skip the fs-related tests when doing code coverage analysis,
# that cause conflicts to the use of host fs between the
# tests and libgcov.
if (NOT CODE_COVERAGE)
  add_subdirectory(dup)
  add_subdirectory(fs)
  add_subdirectory(hostfs)
endif ()

if (UNIX)
  add_subdirectory(datagram)
  add_subdirectory(epoll)
  add_subdirectory(ids)
  add_subdirectory(poller)
  add_subdirectory(sendmsg)
  add_subdirectory(socketpair)
endif ()
