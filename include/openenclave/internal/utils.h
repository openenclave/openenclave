// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_UTILS_H
#define _OE_UTILS_H

#include <openenclave/bits/types.h>
#include <openenclave/internal/defs.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

OE_EXTERNC_BEGIN

/* Round up to the next power of two (or n if already a power of 2) */
OE_INLINE uint32_t oe_round_u32_power2(uint32_t n)
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
OE_INLINE uint64_t oe_round_u64_to_pow2(uint64_t n)
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

OE_INLINE bool oe_is_pow2(size_t n)
{
    return (n != 0) && ((n & (n - 1)) == 0);
}

OE_INLINE bool oe_is_ptrsize_multiple(size_t n)
{
    size_t d = n / sizeof(void*);
    size_t r = n % sizeof(void*);
    return (d >= 1 && r == 0);
}

OE_INLINE unsigned int oe_checksum(const void* data, size_t size)
{
    const unsigned char* p = (const unsigned char*)data;
    unsigned int x = 0;

    while (size--)
        x += *p++;

    return x;
}

OE_INLINE uint64_t oe_round_up_to_multiple(uint64_t x, uint64_t m)
{
    return (x + m - 1) / m * m;
}

OE_INLINE const void* oe_align_pointer(const void* ptr, size_t aligment)
{
    return (const void*)oe_round_up_to_multiple((uint64_t)ptr, aligment);
}

OE_INLINE uint32_t oe_byte_swap32(uint32_t x)
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
#if defined(__linux__)
#define OE_ATOMIC_MEMORY_BARRIER_ACQUIRE() \
    __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define OE_ATOMIC_MEMORY_BARRIER_RELEASE() \
    __atomic_thread_fence(__ATOMIC_RELEASE)
#elif defined(_MSC_VER)
#define OE_ATOMIC_MEMORY_BARRIER_ACQUIRE() _ReadBarrier()
#define OE_ATOMIC_MEMORY_BARRIER_RELEASE() _WriteBarrier()
#else
#error "Unsupported platform"
#endif

#if __x86_64__ || _M_X64
#define OE_CPU_RELAX() asm volatile("pause" ::: "memory")
#elif __aarch64__ || _M_ARM64
/**
 * Future developer:
 * If adding support for ARMv7, use __memory_barrier() instead, and tend to ARM
 * erratum 754327. See cpu_relax() in the Linux sources under
 * arch/arm/include/asm/processor.h.
 */
#define OE_CPU_RELAX() asm volatile("yield" ::: "memory")
#else
#error OE_CPU_RELAX() not implemented for this architecture.
#endif

/**
 * oe_secure_zero_fill is intended to be used to zero out secrets.
 * Plain memset/for-loops can get optimized away be the compiler.
 * Use oe_secure_zero_fill instead.
 */
OE_INLINE void oe_secure_zero_fill(volatile void* ptr, size_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (size--)
    {
        *p++ = 0;
    }
}

/**
 * oe_secure_memcpy guarantees that the memcpy is not optimized away by the
 * compiler.
 */
OE_INLINE void oe_secure_memcpy(
    volatile void* dst,
    const void* src,
    size_t size)
{
    volatile uint8_t* d = (volatile uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    while (size--)
    {
        *d++ = *s++;
    }
}

/**
 * oe_constant_time_mem_equal does a constant time memory compare.
 */
OE_INLINE int oe_constant_time_mem_equal(
    const volatile void* pv1,
    const volatile void* pv2,
    size_t len)
{
    volatile uint8_t* p1 = (uint8_t*)pv1;
    volatile uint8_t* p2 = (uint8_t*)pv2;
    uint8_t r = 0;

    for (uint32_t i = 0; i < len; ++i)
    {
        r = r | (p1[i] ^ p2[i]);
    }

    return !r;
}

OE_INLINE uint64_t oe_round_up_to_page_size(uint64_t x)
{
    uint64_t n = OE_PAGE_SIZE;
    return (x + n - 1) / n * n;
}

OE_INLINE uint64_t oe_round_down_to_page_size(uint64_t x)
{
    return x & ~((uint64_t)OE_PAGE_SIZE - 1);
}

OE_INLINE void oe_mem_reverse_inplace(void* mem, size_t n)
{
    uint8_t* const p = (uint8_t*)mem;
    for (size_t i = 0; i < n / 2; ++i)
    {
        uint8_t x = p[i];
        p[i] = p[n - 1 - i];
        p[n - 1 - i] = x;
    }
}

OE_EXTERNC_END

#endif /* _OE_UTILS_H */
