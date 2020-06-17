// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/syscall/netdb.h>

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
