/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_BITS_IN_H
#define _OE_BITS_IN_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#if __OE_BYTE_ORDER == __OE_BIG_ENDIAN
OE_INLINE uint32_t oe_ntohl(uint32_t x)
{
    return x;
}
OE_INLINE uint16_t oe_ntohs(uint16_t x)
{
    return x;
}
OE_INLINE uint32_t oe_htonl(uint32_t x)
{
    return x;
}
OE_INLINE uint16_t oe_htons(uint16_t x)
{
    return x;
}
#elif defined(MSVC)
OE_INLINE uint32_t oe_ntohl(uint32_t x)
{
    return __byteswap_ulong(x);
}
OE_INLINE uint16_t oe_ntohs(uint16_t x)
{
    return __byteswap_ushort(x);
}
OE_INLINE uint32_t oe_htonl(uint32_t x)
{
    return __byteswap_ulong(x);
}
OE_INLINE uint16_t oe_htons(uint16_t x)
{
    return __byteswap_ushort(x);
}
#else
OE_INLINE uint32_t oe_ntohl(uint32_t x)
{
    return __builtin_bswap32(x);
}
OE_INLINE uint16_t oe_ntohs(uint16_t x)
{
    return __builtin_bswap16(x);
}
OE_INLINE uint32_t oe_htonl(uint32_t x)
{
    return __builtin_bswap32(x);
}
OE_INLINE uint16_t oe_htons(uint16_t x)
{
    return __builtin_bswap16(x);
}
#endif

OE_EXTERNC_END

#endif /* _OE_BITS_IN_H */
