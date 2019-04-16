/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_NETINET_IN_H
#define _OE_NETINET_IN_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Address to accept any incoming messages. */
#define OE_INADDR_ANY ((in_addr_t)0x00000000)

/* Address to send to all hosts. */
#define OE_INADDR_BROADCAST ((in_addr_t)0xffffffff)

/* Address indicating an error return. */
#define OE_INADDR_NONE ((in_addr_t)0xffffffff)

/* Address to loopback in software to local host. */
#define OE_INADDR_LOOPBACK ((in_addr_t)0x7f000001) /* Inet 127.0.0.1.  */

#define OE_SOCK_STREAM 1
#define OE_SOCK_DGRAM 2

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// clang-format off
#define OE_IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define OE_IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
// clang-format on

typedef uint32_t in_addr_t;

struct oe_in_addr
{
    in_addr_t s_addr;
};

struct oe_in6_addr
{
#include <openenclave/corelibc/netinet/bits/in6_addr.h>
};

#define oe_s6_addr __in6_union.__s6_addr
#define oe_s6_addr16 __in6_union.__s6_addr16
#define oe_s6_addr32 __in6_union.__s6_addr32

struct oe_sockaddr_in
{
#include <openenclave/corelibc/netinet/bits/sockaddr_in.h>
};

struct oe_sockaddr_in6
{
#include <openenclave/corelibc/netinet/bits/sockaddr_in6.h>
};

#if defined(OE_NEED_STDC_NAMES)

#define INADDR_ANY OE_INADDR_ANY
#define INADDR_BROADCAST OE_INADDR_BROADCAST
#define INADDR_NONE OE_INADDR_NONE
#define INADDR_LOOPBACK OE_INADDR_LOOPBACK
#define SOCK_STREAM OE_SOCK_STREAM
#define SOCK_DGRAM OE_SOCK_DGRAM
#define IN6ADDR_ANY_INIT OE_IN6ADDR_ANY_INIT
#define IN6ADDR_LOOPBACK_INIT OE_IN6ADDR_LOOPBACK_INIT
#define s6_addr oe_s6_addr
#define s6_addr16 oe_s6_addr16
#define s6_addr32 oe_s6_addr32

struct in_addr
{
    in_addr_t s_addr;
};

struct in6_addr
{
#include <openenclave/corelibc/netinet/bits/in6_addr.h>
};

struct sockaddr_in
{
#include <openenclave/corelibc/netinet/bits/sockaddr_in.h>
};

struct sockaddr_in6
{
#include <openenclave/corelibc/netinet/bits/sockaddr_in6.h>
};

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_NETINET_IN_H */
