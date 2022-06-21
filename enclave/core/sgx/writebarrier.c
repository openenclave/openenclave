// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>

#define ALIGNMENT_MINUS_ONE 7
#define MEMSET_PATTERN_U64 0x0101010101010101
#define MEMSET_PATTERN_U32 0x01010101
#define MEMSET_PATTERN_U16 0x0101

OE_ALWAYS_INLINE
static void _memcpy_aligned(void* dest, const void* src, size_t count)
{
    uint64_t rdi, rsi, rcx;
    asm volatile(
        "shr $3, %2\n\t"
        "rep movsq\n\t"
        : "=D"(rdi), "=S"(rsi), "=c"(rcx) /* rdi, rsi, and rcx are clobbered */
        : "D"(dest), "S"(src), "c"(count)
        : "memory");
}

OE_ALWAYS_INLINE
static void _memset_aligned(void* dest, int character, size_t count)
{
    uint64_t pattern = MEMSET_PATTERN_U64 * (uint8_t)character;

    count = count >> 3;

    for (size_t i = 0; i < count; i++)
        ((uint64_t*)dest)[i] = pattern;
}

OE_NEVER_INLINE
static void* _memset_unaligned_with_barrier(
    void* dest,
    int character,
    size_t count)
{
    uint64_t dest_addr = (uint64_t)dest;

    while (count >= 8)
    {
        if (dest_addr % 8 == 0)
        {
            /* for 8-byte-aligned memory, use regular memset with the size being
             * the multiples of 8 */
            size_t count_aligned = count - count % 8;
            _memset_aligned((void*)dest_addr, character, count_aligned);
            dest_addr += count_aligned;
            count -= count_aligned;
        }
        else
        {
            /* for non-8-byte-aligned memory, use the greedy approach to find
             * the optimized-size write with barrier */
            uint64_t next_aligned_addr = (dest_addr + ALIGNMENT_MINUS_ONE) &
                                         ~(uint64_t)ALIGNMENT_MINUS_ONE;
            uint64_t gap_count;

            while ((gap_count = next_aligned_addr - dest_addr))
            {
                if (gap_count >= 4)
                {
                    OE_WRITE_VALUE_WITH_BARRIER(
                        (void*)dest_addr,
                        (uint32_t)((uint8_t)character * MEMSET_PATTERN_U32));
                    dest_addr += 4;
                    count -= 4;
                }
                else if (gap_count >= 2)
                {
                    OE_WRITE_VALUE_WITH_BARRIER(
                        (void*)dest_addr,
                        (uint16_t)((uint8_t)character * MEMSET_PATTERN_U16));
                    dest_addr += 2;
                    count -= 2;
                }
                else
                {
                    OE_WRITE_VALUE_WITH_BARRIER(
                        (void*)dest_addr, (uint8_t)character);
                    dest_addr++;
                    count--;
                }
            }
        }
    }

    while (count)
    {
        if (count >= 4)
        {
            OE_WRITE_VALUE_WITH_BARRIER(
                (void*)dest_addr,
                (uint32_t)((uint8_t)character * MEMSET_PATTERN_U32));
            dest_addr += 4;
            count -= 4;
        }
        else if (count >= 2)
        {
            OE_WRITE_VALUE_WITH_BARRIER(
                (void*)dest_addr,
                (uint16_t)((uint8_t)character * MEMSET_PATTERN_U16));
            dest_addr += 2;
            count -= 2;
        }
        else
        {
            OE_WRITE_VALUE_WITH_BARRIER((void*)dest_addr, (uint8_t)character);
            dest_addr++;
            count--;
        }
    }

    return dest;
}

void* oe_memset_with_barrier(void* dest, int value, size_t count)
{
    /* If both dest and count are 8-byte aligned, fallback to regular
     * (fast) memset. For the other cases, use the hardened version of memset.
     * Note that the hardened memset should not be inline, otherwise the
     * fence instructions in branches will slowdown the fallback path. */
    if (((uint64_t)dest % 8 == 0) && (count % 8 == 0))
        _memset_aligned(dest, value, count);
    else
        _memset_unaligned_with_barrier(dest, value, count);

    return dest;
}

OE_NEVER_INLINE
static void* _memcpy_unaligned_with_barrier(
    void* dest,
    const void* src,
    size_t count)
{
    uint64_t dest_addr = (uint64_t)dest;
    uint64_t src_addr = (uint64_t)src;

    while (count >= 8)
    {
        if (dest_addr % 8 == 0)
        {
            /* for 8-byte-aligned memory, use regular memcpy with the size being
             * the multiples of 8 */
            size_t count_aligned = count - count % 8;
            _memcpy_aligned(
                (void*)dest_addr, (const void*)src_addr, count_aligned);
            src_addr += count_aligned;
            dest_addr += count_aligned;
            count -= count_aligned;
        }
        else
        {
            /* for non-8-byte-aligned memory, use the greedy approach to find
             * the optimized-size write with barrier */
            uint64_t next_aligned_addr = (dest_addr + ALIGNMENT_MINUS_ONE) &
                                         ~(uint64_t)ALIGNMENT_MINUS_ONE;
            uint64_t gap_count;

            while ((gap_count = next_aligned_addr - dest_addr))
            {
                if (gap_count >= 4 && (src_addr % 4) == 0)
                {
                    OE_WRITE_VALUE_WITH_BARRIER(
                        (void*)dest_addr, *(uint32_t*)src_addr);
                    dest_addr += 4;
                    src_addr += 4;
                    count -= 4;
                }
                else if (gap_count >= 2 && (src_addr % 2) == 0)
                {
                    OE_WRITE_VALUE_WITH_BARRIER(
                        (void*)dest_addr, *(uint16_t*)src_addr);
                    dest_addr += 2;
                    src_addr += 2;
                    count -= 2;
                }
                else
                {
                    OE_WRITE_VALUE_WITH_BARRIER(
                        (void*)dest_addr, *(uint8_t*)src_addr);
                    dest_addr++;
                    src_addr++;
                    count--;
                }
            }
        }
    }

    /* use the greedy approach to find the optimized-size write with barrier for
     * the reset of the memory */
    while (count)
    {
        if (count >= 4 && (src_addr % 4) == 0)
        {
            OE_WRITE_VALUE_WITH_BARRIER((void*)dest_addr, *(uint32_t*)src_addr);
            dest_addr += 4;
            src_addr += 4;
            count -= 4;
        }
        else if (count >= 2 && (src_addr % 2) == 0)
        {
            OE_WRITE_VALUE_WITH_BARRIER((void*)dest_addr, *(uint16_t*)src_addr);
            dest_addr += 2;
            src_addr += 2;
            count -= 2;
        }
        else
        {
            OE_WRITE_VALUE_WITH_BARRIER((void*)dest_addr, *(uint8_t*)src_addr);
            dest_addr++;
            src_addr++;
            count--;
        }
    }

    return dest;
}

void* oe_memcpy_with_barrier(void* dest, const void* src, size_t count)
{
    /* If both dest and count are 8-byte aligned, fallback to regular
     * (fast) memcpy. For the other cases, use the hardened version of memcpy.
     * Note that the hardened memcpy should not be inline, otherwise the
     * fence instructions in branches will slowdown the fallback path. */
    if (((uint64_t)dest % 8 == 0) && (count % 8 == 0))
        _memcpy_aligned(dest, src, count);
    else
        _memcpy_unaligned_with_barrier(dest, src, count);

    return dest;
}

OE_NEVER_INLINE
static void _memmove_with_barrier(void* dest, const void* src, size_t count)
{
    if (dest < src)
    {
        /* If the destination is less than source, use the hardened version
         * of memcpy */
        oe_memcpy_with_barrier(dest, src, count);
    }
    else
    {
        /* If the destination is greater than the source, use the hardened write
         * to copy byte-by-byte backward */
        uint64_t dest_addr = (uint64_t)dest + count - 1;
        uint64_t src_addr = (uint64_t)src + count - 1;

        while (count)
        {
            OE_WRITE_VALUE_WITH_BARRIER((void*)dest_addr, *(uint8_t*)src_addr);
            dest_addr--;
            src_addr--;
            count--;
        }
    }
}

void* oe_memmove_with_barrier(void* dest, const void* src, size_t count)
{
    /* Overlapping case can only occur if dest and src are both in the
     * enclave or host memory */
    if ((dest >= src && ((uint8_t*)dest < ((uint8_t*)src + count))) ||
        (dest < src && ((uint8_t*)dest + count > (uint8_t*)src)))
    {
        /* If the dest is in the enclave memory, fallback to regular memmove */
        if (oe_is_within_enclave(dest, count))
            memmove(dest, src, count);
        else /* otherwise, use the hardened version of memmove */
            _memmove_with_barrier(dest, src, count);
    }
    else /* use the hardened version of memcpy to handle non-overlapping cases
          */
        oe_memcpy_with_barrier(dest, src, count);

    return dest;
}

oe_result_t oe_memcpy_s_with_barrier(
    void* dest,
    size_t dest_count,
    const void* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;

    /* Check if [dest, dest + dest_count] is valid */
    if (dest == NULL || ((uint64_t)dest + dest_count < (uint64_t)dest))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check if [src, src + num_bytes] and num_bytes is valid */
    if (src == NULL || ((uint64_t)src + num_bytes < (uint64_t)src) ||
        dest_count < num_bytes)
    {
        oe_memset_with_barrier(dest, 0, dest_count);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Reject overlapping buffers. */
    if ((dest >= src && ((uint64_t)dest < (uint64_t)src + num_bytes)) ||
        (dest < src && ((uint64_t)dest + dest_count > (uint64_t)src)))
    {
        oe_memset_with_barrier(dest, 0, dest_count);
        OE_RAISE(OE_OVERLAPPED_COPY);
    }

    oe_memcpy_with_barrier(dest, src, num_bytes);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_memmove_s_with_barrier(
    void* dest,
    size_t dest_count,
    const void* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;

    /* Check if [dest, dest + dest_count] is valid */
    if (dest == NULL || ((uint64_t)dest + dest_count < (uint64_t)dest))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check if [src, src + num_bytes] and num_bytes is valid */
    if (src == NULL || ((uint64_t)src + num_bytes < (uint64_t)src) ||
        dest_count < num_bytes)
    {
        oe_memset_with_barrier(dest, 0, dest_count);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    oe_memmove_with_barrier(dest, src, num_bytes);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_memset_s_with_barrier(
    void* dest,
    size_t dest_count,
    int value,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;

    if (dest == NULL || ((uint64_t)dest + dest_count < (uint64_t)dest))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The C11 standard states that memset_s will store `value` in
     * `dest[0...dest_count]` even during a runtime violation. */
    if (dest_count < num_bytes)
    {
        result = OE_INVALID_PARAMETER;
        num_bytes = dest_count;
    }
    else
    {
        result = OE_OK;
    }

    oe_memset_with_barrier(dest, value, num_bytes);

done:
    return result;
}
