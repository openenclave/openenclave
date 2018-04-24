// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
    return ((uint32_t)((x & 0x000000FF) << 24)) |
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

/**
 * Acquire and Release memory barriers for open enclave.
 *
 * An acquire barrier prevents the memory reordering of any read which precedes
 * it in program order with any read or write which follows it in program order.
 * A release barrier prevents the memory reordering of any read or write which
 * precedes it in program order with any write which follows it in program
 * order.
 *
 * Barriers generally operate both at the compiler level as well as at the
 * processor level. x86 is a strongly ordered platform and the acquire and
 * release barriers do not generate any additional machine code. However, they
 * act as bi-directional compiler barriers. For more information, see
 * Release-Acquire ordering in
 * http://en.cppreference.com/w/cpp/atomic/memory_order. For a deeper
 * understanding see "C++ and the Perils of Double-Checked Locking"
 * http://www.aristeia.com/Papers/DDJ_Jul_Aug_2004_revised.pdf.
*/
#define OE_ATOMIC_MEMORY_BARRIER_ACQUIRE() asm volatile("" ::: "memory")
#define OE_ATOMIC_MEMORY_BARRIER_RELEASE() asm volatile("" ::: "memory")

/**
 * OE_Memset_s is intended to be used to zero out secrets.
 * Plain memset/for-loops can get optimized away be the compiler.
 * Use OE_Memset_s instead.
 */
OE_INLINE void OE_Memset_s(volatile void* pv, int v, uint32_t len)
{
    volatile uint8_t* p = (volatile uint8_t*)pv;
    for (uint32_t i = 0; i < len; ++i)
    {
        p[i] = 0;
    }
}

/**
 * OE_Memequal_s does a constant time memory compare.
 */
OE_INLINE int OE_Memequal_s(
    const volatile void* pv1,
    const volatile void* pv2,
    uint32_t len)
{
    volatile uint8_t* p1 = (uint8_t*)pv1;
    volatile uint8_t* p2 = (uint8_t*)pv2;
    uint8_t r = 0;

    for (uint32_t i = 0; i < len; ++i)
    {
        r |= p1[i] ^ p2[i];
    }

    return !r;
}

OE_EXTERNC_END

#endif /* _OE_UTILS_H */
