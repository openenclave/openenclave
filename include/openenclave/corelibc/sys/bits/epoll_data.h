// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

typedef union __OE_STRUCT_EPOLL_DATA {
    void* ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} __OE_TYPEDEF_EPOLL_DATA;
