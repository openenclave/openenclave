# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/poller_select poller_host poller_enc select)
add_enclave_test(tests/poller_poll poller_host poller_enc poll)
add_enclave_test(tests/poller_epoll poller_host poller_enc epoll)
