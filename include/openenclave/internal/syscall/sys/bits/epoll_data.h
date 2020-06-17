// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

typedef union __OE_EPOLL_DATA {
    void* ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} __OE_EPOLL_DATA_T;
