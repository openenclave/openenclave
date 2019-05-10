/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_ARPA_INET_H
#define _OE_ARPA_INET_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/netinet/in.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

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

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

OE_INLINE uint32_t ntohl(uint32_t x)
{
    return oe_ntohl(x);
}

OE_INLINE uint16_t ntohs(uint16_t x)
{
    return oe_ntohs(x);
}

OE_INLINE uint32_t htonl(uint32_t x)
{
    return oe_htonl(x);
}

OE_INLINE uint16_t htons(uint16_t x)
{
    return oe_htons(x);
}

OE_INLINE uint32_t inet_addr(const char* cp)
{
    return oe_inet_addr(cp);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_ARPA_INET_H */
