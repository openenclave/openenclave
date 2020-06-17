// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/syscall/netdb.h>

struct addrinfo;

void freeaddrinfo(struct addrinfo* res)
{
    oe_freeaddrinfo((struct oe_addrinfo*)res);
}
