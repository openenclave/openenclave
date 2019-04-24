// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

struct __OE_STRUCT_SOCKADDR_IN6
{
    sa_family_t sin6_family;
    in_port_t sin6_port;
    uint32_t sin6_flowinfo;
    struct oe_in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};
