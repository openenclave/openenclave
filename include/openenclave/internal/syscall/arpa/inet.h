/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef OE_SYSCALL_ARPA_INET_H
#define OE_SYSCALL_ARPA_INET_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/syscall/netinet/in.h>

OE_EXTERNC_BEGIN

#define __OE_LITTLE_ENDIAN 1234
#define __OE_BIG_ENDIAN 4321

#if defined(__i386) || defined(__x86_64)
#define __OE_BYTE_ORDER __OE_LITTLE_ENDIAN
#elif defined(__arm__) || defined(__aarch64__)
#define __OE_BYTE_ORDER __OE_BIG_ENDIAN
#elif defined(_WIN32)
#define __OE_BYTE_ORDER __OE_LITTLE_ENDIAN
#endif

OE_INLINE uint32_t oe_ntohl(uint32_t x)
{
#if __OE_BYTE_ORDER == __OE_BIG_ENDIAN
    return x;
#else
    return __builtin_bswap32(x);
#endif
}

OE_INLINE uint16_t oe_ntohs(uint16_t x)
{
#if __OE_BYTE_ORDER == __OE_BIG_ENDIAN
    return x;
#else
    return __builtin_bswap16(x);
#endif
}

OE_INLINE uint32_t oe_htonl(uint32_t x)
{
#if __OE_BYTE_ORDER == __OE_BIG_ENDIAN
    return x;
#else
    return __builtin_bswap32(x);
#endif
}

OE_INLINE uint16_t oe_htons(uint16_t x)
{
#if __OE_BYTE_ORDER == __OE_BIG_ENDIAN
    return x;
#else
    return __builtin_bswap16(x);
#endif
}

uint32_t oe_inet_addr(const char* cp);

OE_EXTERNC_END

#endif /* OE_SYSCALL_ARPA_INET_H */
