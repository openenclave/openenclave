// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
