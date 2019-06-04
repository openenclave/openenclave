// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/netdb.h>

struct addrinfo;

int getaddrinfo(
    const char* node,
    const char* service,
    const struct addrinfo* hints,
    struct addrinfo** res)
{
    return oe_getaddrinfo(
        node,
        service,
        (const struct oe_addrinfo*)hints,
        (struct oe_addrinfo**)res);
}
