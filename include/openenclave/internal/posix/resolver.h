// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_RESOLVER_H
#define _OE_POSIX_RESOLVER_H

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/netdb.h>

OE_EXTERNC_BEGIN

typedef struct _oe_resolver oe_resolver_t;

typedef enum _oe_resolver_type
{
    OE_RESOLVER_ENCLAVE_LOCAL = 0,
    OE_RESOLVER_ENCLAVE_DNS = 1,
    OE_RESOLVER_HOST = 2,
} oe_resolver_type_t;

typedef struct _oe_resolver_ops
{
    int (*getaddrinfo)(
        oe_resolver_t* dev,
        const char* node,
        const char* service,
        const struct oe_addrinfo* hints,
        struct oe_addrinfo** res);

    ssize_t (*getnameinfo)(
        oe_resolver_t* dev,
        const struct oe_sockaddr* sa,
        oe_socklen_t salen,
        char* host,
        oe_socklen_t hostlen,
        char* serv,
        oe_socklen_t servlen,
        int flags);

    int (*shutdown)(oe_resolver_t* dev);

} oe_resolver_ops_t;

typedef struct _oe_resolver
{
    oe_resolver_type_t type;
    oe_resolver_ops_t* ops;
} oe_resolver_t;

int oe_register_resolver(int resolver_priority, oe_resolver_t* presolver);

OE_EXTERNC_END

#endif /* _OE_POSIX_RESOLVER_H */
