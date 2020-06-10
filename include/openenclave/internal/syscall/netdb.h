// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_NETDB_H_
#define _OE_SYSCALL_NETDB_H_

#include <openenclave/internal/bits/socket.h>
#include <openenclave/internal/syscall/sys/socket.h>

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

int oe_getaddrinfo(
    const char* node,
    const char* service,
    const struct oe_addrinfo* hints,
    struct oe_addrinfo** res);

void oe_freeaddrinfo(struct oe_addrinfo* res);

int oe_getnameinfo(
    const struct oe_sockaddr* sa,
    oe_socklen_t salen,
    char* host,
    oe_socklen_t hostlen,
    char* serv,
    oe_socklen_t servlen,
    int flags);

OE_EXTERNC_END

#endif /* netinet/netdb.h */
