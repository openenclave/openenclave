// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

struct __OE_SOCKADDR_IN
{
    oe_sa_family_t sin_family;
    oe_in_port_t sin_port;
    struct oe_in_addr sin_addr;
    uint8_t sin_zero[8];
};
