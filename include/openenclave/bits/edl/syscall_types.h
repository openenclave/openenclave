// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EDL_SYSCALL_TYPES_H
#define _OE_EDL_SYSCALL_TYPES_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

/* DISCLAIMER:
 * This header is published with no guarantees of stability and is not part
 * of the Open Enclave public API surface. It is only intended to be used
 * internally by the OE runtime. */

typedef int64_t oe_host_fd_t;

typedef uint64_t oe_nfds_t;

typedef union _oe_epoll_data_t {
    void* ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} oe_epoll_data_t;

/*
 * The epoll events are packed in x86_64 but not on other architectures. This is
 * probably because the x86 has no problem with unaligned accesses where as
 * unaligned accesses are usually very inefficient, even if they are allowed, in
 * other architectures. We maintain consistency with MUSL's and the linux
 * kernel's handling on that architecture.
 */
#if !defined(__aarch64__)
OE_PACK_BEGIN
#endif
struct oe_epoll_event
{
    uint32_t events;
    oe_epoll_data_t data;
};
#if !defined(__aarch64__)
OE_PACK_END
#endif

#endif // _OE_EDL_SYSCALL_TYPES_H
