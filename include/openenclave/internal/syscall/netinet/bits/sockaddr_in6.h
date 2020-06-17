// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

struct __OE_SOCKADDR_IN6
{
    oe_sa_family_t sin6_family;
    oe_in_port_t sin6_port;
    uint32_t sin6_flowinfo;
    struct oe_in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};
