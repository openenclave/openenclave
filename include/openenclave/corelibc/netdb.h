// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_NETDB_H_
#define _OE_CORELIBC_NETDB_H_

#include <openenclave/corelibc/sys/socket.h>

OE_EXTERNC_BEGIN

#define OE_AI_PASSIVE 0x01
#define OE_AI_CANONNAME 0x02
#define OE_AI_NUMERICHOST 0x04
#define OE_AI_V4MAPPED 0x08
#define OE_AI_ALL 0x10
#define OE_AI_ADDRCONFIG 0x20
#define OE_AI_NUMERICSERV 0x400

#define OE_NI_NUMERICHOST 0x01
#define OE_NI_NUMERICSERV 0x02
#define OE_NI_NOFQDN 0x04
#define OE_NI_NAMEREQD 0x08
#define OE_NI_DGRAM 0x10
#define OE_NI_NUMERICSCOPE 0x100

#define OE_EAI_BADFLAGS -1
#define OE_EAI_NONAME -2
#define OE_EAI_AGAIN -3
#define OE_EAI_FAIL -4
#define OE_EAI_FAMILY -6
#define OE_EAI_SOCKTYPE -7
#define OE_EAI_SERVICE -8
#define OE_EAI_MEMORY -10
#define OE_EAI_SYSTEM -11
#define OE_EAI_OVERFLOW -12
#define OE_EAI_NODATA -5
#define OE_EAI_ADDRFAMILY -9
#define OE_EAI_INPROGRESS -100
#define OE_EAI_CANCELED -101
#define OE_EAI_NOTCANCELED -102
#define OE_EAI_ALLDONE -103
#define OE_EAI_INTR -104
#define OE_EAI_IDN_ENCODE -105
#define OE_NI_MAXHOST 255
#define OE_NI_MAXSERV 32

#define __OE_STRUCT_ADDRINFO oe_addrinfo
#define __OE_STRUCT_SOCKADDR oe_sockaddr
#include <openenclave/corelibc/bits/addrinfo.h>
#undef __OE_STRUCT_ADDRINFO
#undef __OE_STRUCT_SOCKADDR

int oe_getaddrinfo(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo** res);

void oe_freeaddrinfo(struct oe_addrinfo* res);

int oe_getnameinfo(
    const struct oe_sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags);

#if defined(OE_NEED_STDC_NAMES)

#define AI_PASSIVE OE_AI_PASSIVE
#define AI_CANONNAME OE_AI_CANONNAME
#define AI_NUMERICHOST OE_AI_NUMERICHOST
#define AI_V4MAPPED OE_AI_V4MAPPED
#define AI_ALL OE_AI_ALL
#define AI_ADDRCONFIG OE_AI_ADDRCONFIG
#define AI_NUMERICSERV OE_AI_NUMERICSERV
#define NI_NUMERICHOST OE_NI_NUMERICHOST
#define NI_NUMERICSERV OE_NI_NUMERICSERV
#define NI_NOFQDN OE_NI_NOFQDN
#define NI_NAMEREQD OE_NI_NAMEREQD
#define NI_DGRAM OE_NI_DGRAM
#define NI_NUMERICSCOPE OE_NI_NUMERICSCOPE
#define EAI_BADFLAGS OE_EAI_BADFLAGS
#define EAI_NONAME OE_EAI_NONAME
#define EAI_AGAIN OE_EAI_AGAIN
#define EAI_FAIL OE_EAI_FAIL
#define EAI_FAMILY OE_EAI_FAMILY
#define EAI_SOCKTYPE OE_EAI_SOCKTYPE
#define EAI_SERVICE OE_EAI_SERVICE
#define EAI_MEMORY OE_EAI_MEMORY
#define EAI_SYSTEM OE_EAI_SYSTEM
#define EAI_OVERFLOW OE_EAI_OVERFLOW
#define EAI_NODATA OE_EAI_NODATA
#define EAI_ADDRFAMILY OE_EAI_ADDRFAMILY
#define EAI_INPROGRESS OE_EAI_INPROGRESS
#define EAI_CANCELED OE_EAI_CANCELED
#define EAI_NOTCANCELED OE_EAI_NOTCANCELED
#define EAI_ALLDONE OE_EAI_ALLDONE
#define EAI_INTR OE_EAI_INTR
#define EAI_IDN_ENCODE OE_EAI_IDN_ENCODE
#define NI_MAXHOST OE_NI_MAXHOST
#define NI_MAXSERV OE_NI_MAXSERV

#define __OE_STRUCT_ADDRINFO addrinfo
#define __OE_STRUCT_SOCKADDR sockaddr
#include <openenclave/corelibc/bits/addrinfo.h>
#undef __OE_STRUCT_ADDRINFO
#undef __OE_STRUCT_SOCKADDR

OE_INLINE int getaddrinfo(
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

OE_INLINE void freeaddrinfo(struct addrinfo* res)
{
    return oe_freeaddrinfo((struct oe_addrinfo*)res);
}

OE_INLINE int getnameinfo(
    const struct sockaddr* sa,
    socklen_t salen,
    char* host,
    socklen_t hostlen,
    char* serv,
    socklen_t servlen,
    int flags)
{
    return oe_getnameinfo(
        (const struct oe_sockaddr*)sa,
        salen,
        host,
        hostlen,
        serv,
        servlen,
        flags);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* netinet/netdb.h */
