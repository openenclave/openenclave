// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RESOLVER_H
#define _OE_RESOLVER_H

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/netdb.h>

// typedef uint32_t socklen_t;

OE_EXTERNC_BEGIN

typedef struct _oe_resolver oe_resolver_t;

typedef struct _oe_resolver_ops
{
    ssize_t (*getaddrinfo_r)(
        oe_resolver_t* dev,
        const char* node,
        const char* service,
        const struct oe_addrinfo* hints,
        struct oe_addrinfo* res,
        ssize_t* buffersize);

    void (*freeaddrinfo)(oe_resolver_t* dev, struct oe_addrinfo* res);

    ssize_t (*getnameinfo)(
        oe_resolver_t* dev,
        const struct oe_sockaddr* sa,
        socklen_t salen,
        char* host,
        socklen_t hostlen,
        char* serv,
        socklen_t servlen,
        int flags);

    // 2Do:     gethostbyaddr(3), getservbyname(3), getservbyport(3),
    int (*shutdown)(oe_resolver_t* dev);

} oe_resolver_ops_t;

// Well known resolver ids
static const int OE_RESOLVER_ENCLAVE_LOCAL = 0;
static const int OE_RESOLVER_ENCLAVE_DNS = 1; //
static const int OE_RESOLVER_HOST = 2;

typedef struct _oe_resolver
{
    /* Type of this device: OE_DEVID_FILE or OE_DEVID_SOCKET. */
    int type;

    /* sizeof additional data. To get a pointer to the device private data,
     * ptr = (oe_file_device_t)(devptr+1); usually sizeof(oe_file_t) or
     * sizeof(oe_socket_t).
     */
    size_t size;

    oe_resolver_ops_t* ops;

} oe_resolver_t;

int oe_register_resolver(int resolver_priority, oe_resolver_t* presolver);
OE_EXTERNC_END

#endif
