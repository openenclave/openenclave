#ifndef _OE_UTILS_H
#define _OE_UTILS_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

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

OE_INLINE unsigned int OE_Checksum(const void* data, size_t size)
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

OE_INLINE const void* OE_AlignPointer(const void* ptr, size_t aligment)
{
    return (const void*)OE_RoundUpToMultiple((uint64_t)ptr, aligment);
}

OE_INLINE uint32_t OE_ByteSwap32(uint32_t x)
{
    return
        ((uint32_t)((x & 0x000000FF) << 24)) |
        ((uint32_t)((x & 0x0000FF00) << 8)) |
        ((uint32_t)((x & 0x00FF0000) >> 8)) |
        ((uint32_t)((x & 0xFF000000) >> 24));
}

/**
 *==============================================================================
 *
 * Calculates a numeric code for a string.
 *
 * This function calculates a code for the **s** string parameter. If the codes
 * for two strings are identical, then the following are true:
 *     - The strings have the same length
 *     - The strings have the same first character
 *     - The strings have the same last character
 *
 * If strings 's1' and 's2' have the same code, then the strings are identical
 * if the following expression is true.
 *
 *     memcmp(&s1[1], &s2[1], len-2) == 0
 *
 * where 'len' is the length of either of the strings.
 *
 * If the string is null, this function will crash. If the string is empty,
 * the results are undefined. The caller is responsible for passing a non-null,
 * non-empty string to this function.
 *
 * @param s Pointer to a non-null, non-empty string
 *
 * @returns The string code for the **s** parameter
 *
 *==============================================================================
 */
OE_INLINE uint64_t StrCode(const char* s, uint64_t n)
{
    return (uint64_t)s[0] | ((uint64_t)s[n - 1] << 8) | ((uint64_t)n << 16);
}

OE_EXTERNC_END

#endif /* _OE_UTILS_H */
