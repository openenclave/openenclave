// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_RESOLVER_H
#define _OE_INTERNAL_POSIX_RESOLVER_H

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/netdb.h>

OE_EXTERNC_BEGIN

typedef struct _oe_resolver oe_resolver_t;

#define OE_RESOLVER_ENCLAVE_LOCAL 0
#define OE_RESOLVER_ENCLAVE_DNS 1
#define OE_RESOLVER_HOST 2

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
        socklen_t salen,
        char* host,
        socklen_t hostlen,
        char* serv,
        socklen_t servlen,
        int flags);

    int (*shutdown)(oe_resolver_t* dev);

} oe_resolver_ops_t;

typedef struct _oe_resolver
{
    /* The type of the device. */
    int type;

    oe_resolver_ops_t* ops;

} oe_resolver_t;

int oe_register_resolver(int resolver_priority, oe_resolver_t* presolver);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_POSIX_RESOLVER_H */
