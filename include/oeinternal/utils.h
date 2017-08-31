#ifndef _OE_UTILS_H
#define _OE_UTILS_H

#include "../oecommon/defs.h"
#include "../oecommon/types.h"

OE_EXTERNC_BEGIN

/* Round up to the next power of two (or n if already a power of 2) */
OE_INLINE uint32_t OE_RoundU32Power2(uint32_t n)
{
    uint32_t x = n - 1;
    x |= (x >> 1);
    x |= (x >> 2);
    x |= (x >> 4);
    x |= (x >> 8);
    x |= (x >> 16);
    return x + 1;
}

/* Round up to the next power of two (or n if already a power of 2) */
OE_INLINE uint64_t OE_RoundU64ToPow2(uint64_t n)
{
    uint64_t x = n - 1;
    x |= (x >> 1);
    x |= (x >> 2);
    x |= (x >> 4);
    x |= (x >> 8);
    x |= (x >> 16);
    x |= (x >> 32);
    return x + 1;
}

OE_INLINE unsigned int OE_Checksum(
    const void* data,
    size_t size)
{
    const unsigned char* p = (const unsigned char*)data;
    unsigned int x = 0;

    while (size--)
        x += *p++;

    return x;
}

OE_INLINE unsigned long long OE_RoundUpToMultiple(
    unsigned long long x,
    unsigned long long m)
{
    return (x + m - 1) / m * m;
}

void __OE_HexDump(
    const void* data_,
    size_t size);

OE_EXTERNC_END

#endif /* _OE_UTILS_H */
