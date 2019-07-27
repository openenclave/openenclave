// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
struct __OE_EPOLL_EVENT
{
    uint32_t events;
    oe_epoll_data_t data;
};
#if !defined(__aarch64__)
OE_PACK_END
#endif
