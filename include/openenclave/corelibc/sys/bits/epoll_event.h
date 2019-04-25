// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

OE_PACK_BEGIN
struct __OE_EPOLL_EVENT
{
    uint32_t events;
    oe_epoll_data_t data;
};
OE_PACK_END
