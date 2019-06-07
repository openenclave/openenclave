/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_SYSCALL_NETINET_IN_H
#define _OE_SYSCALL_NETINET_IN_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/bits/types.h>

OE_EXTERNC_BEGIN

/* Address to accept any incoming messages. */
#define OE_INADDR_ANY ((oe_in_addr_t)0x00000000)

/* Address to send to all hosts. */
#define OE_INADDR_BROADCAST ((oe_in_addr_t)0xffffffff)

/* Address indicating an error return. */
#define OE_INADDR_NONE ((oe_in_addr_t)0xffffffff)

/* Address to loopback in software to local host. */
#define OE_INADDR_LOOPBACK ((oe_in_addr_t)0x7f000001) /* Inet 127.0.0.1.  */

#define OE_SOCK_STREAM 1
#define OE_SOCK_DGRAM 2

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// clang-format off
#define OE_IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define OE_IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
// clang-format on

struct oe_in_addr
{
    oe_in_addr_t s_addr;
};

#define __OE_IN6_ADDR oe_in6_addr
#include <openenclave/internal/syscall/netinet/bits/in6_addr.h>
#undef __OE_IN6_ADDR

#define oe_s6_addr __in6_union.__s6_addr
#define oe_s6_addr16 __in6_union.__s6_addr16
#define oe_s6_addr32 __in6_union.__s6_addr32

#define __OE_SOCKADDR_IN oe_sockaddr_in
#include <openenclave/internal/syscall/netinet/bits/sockaddr_in.h>
#undef __OE_SOCKADDR_IN

#define __OE_SOCKADDR_IN6 oe_sockaddr_in6
#include <openenclave/internal/syscall/netinet/bits/sockaddr_in6.h>
#undef __OE_SOCKADDR_IN6

OE_EXTERNC_END

#endif /* _OE_SYSCALL_NETINET_IN_H */
