// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_BITS_SGX_WRITEBARRIER_H
#define _OE_BITS_SGX_WRITEBARRIER_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#ifdef __GNUC__
/**
 * memcpy for 8-byte aligned count.
 *
 * @param[out] dest Memory where the content is to be copied.
 * @param[in] src A pointer to the source of data to be copied.
 * @param[in] count The number of bytes to be copied.
 *
 */
OE_ALWAYS_INLINE
void oe_memcpy_aligned(void* dest, const void* src, size_t count)
{
    uint64_t rdi, rsi, rcx;
    asm volatile(
        "shr $3, %2\n\t"
        "rep movsq\n\t"
        : "=D"(rdi), "=S"(rsi), "=c"(rcx) /* rdi, rsi, and rcx are clobbered */
        : "D"(dest), "S"(src), "c"(count)
        : "memory");
}
#endif

/**
 * Hardened version of memory copy against the MMIO-based vulnerability.
 *
 * This function copies **count** bytes of memory from **src** to **dest**
 * addresses with mitigation against MMIO-based vulnerability. The function
 * should be used only if the destination address lies in host memory.
 *
 * @param[out] dest Memory where the content is to be copied.
 * @param[in] src A pointer to the source of data to be copied.
 * @param[in] count The number of bytes to be copied.
 *
 * @returns A pointer to destination memory.
 */
void* oe_memcpy_with_barrier(void* dest, const void* src, size_t count);

/**
 * Hardened version of memory move against the MMIO-based vulnerability.
 *
 * This function copies **count** bytes of memory from **src** to **dest**
 * addresses with mitigation against MMIO-based vulnerability. The function
 * should be used only if the destination address lies in host memory.
 *
 * @param[out] dest Memory where the content is to be copied.
 * @param[in] src A pointer to the source of data to be copied.
 * @param[in] count The number of bytes to be copied.
 *
 * @returns A pointer to destination memory.
 */

void* oe_memmove_with_barrier(void* dest, const void* src, size_t count);
/**
 * Hardened version of memory set against the MMIO-based vulnerability.
 *
 * This function copies **count** bytes of **value** character to the **dest**
 * address with mitigation against MMIO-based vulnerability. The function
 * should be used only if the destination address lies in host memory.
 *
 * @param[out] dest A Memory where the content is to be set.
 * @param[in] value The value to be set.
 * @param[in] count The number of bytes to be set.
 *
 * @returns A pointer to destination memory.
 */
void* oe_memset_with_barrier(void* dest, int value, size_t count);

/**
 * Hardened version of secure memory copy against the MMIO-based vulnerability.
 *
 * In addition memory copy, the function validates the input parameters,
 * ensuring memory ranges pointed by **dest** and **src** are valid,
 * **dest_count** is greater than or equal to **num_bytes**, and **dest** does
 * not overlap with
 * **src**. The function should be used only if the destination address lies in
 * host memory.
 *
 * @param[out] dest Memory where the content is to be copied.
 * @param[in] dest_count The count of the memory pointed by **dest**.
 * @param[in] src A pointer to the source of data to be copied.
 * @param[in] num_bytes The number of bytes to be copied.
 *
 * @returns A pointer to destination memory.
 */
oe_result_t oe_memcpy_s_with_barrier(
    void* dest,
    size_t dest_count,
    const void* src,
    size_t num_bytes);

/**
 * Hardened version of secure memory move against the MMIO-based vulnerability.
 *
 * In addition memory copy, the function validates the input parameters,
 * ensuring memory ranges pointed by **dest** and **src** are valid,
 * **dest_count** is greater than or equal to **num_bytes**. The function should
 * be used only if the destination address lies in host memory.
 *
 * @param[out] dest Memory where the content is to be copied.
 * @param[in] dest_count The count of the memory pointed by **dest**.
 * @param[in] src A pointer to the source of data to be copied.
 * @param[in] num_bytes The number of bytes to be copied.
 *
 * @returns A pointer to destination memory.
 */
oe_result_t oe_memmove_s_with_barrier(
    void* dest,
    size_t dest_count,
    const void* src,
    size_t num_bytes);

/**
 * Hardened version of secure memory set against the MMIO-based vulnerability.
 *
 * In addition to memory set, the function validates the input parameters,
 * ensuring **dest_count** is greater than or equal to **num_bytes**. The
 * function should be used only if the destination address lies in host memory.
 *
 * @param[in] dest Memory where the content is to be set.
 * @param[in] dest_count The count of the memory pointed by **dest**.
 * @param[in] value The value to be set.
 * @param[in] num_bytes The number of bytes to be set.
 *
 * @returns A pointer to destination memory.
 */
oe_result_t oe_memset_s_with_barrier(
    void* dest,
    size_t dest_count,
    int value,
    size_t num_bytes);

/*
 * Write value to host memory with barrier.
 *
 * The value requires explicit type-casted if it is constant.
 * Only standard types are allowed (e.g., the size of the type
 * should be 8-byte, 4-byte, 2-byte, or 1-byte). Otherwise, the
 * asm function would cause compiler errors.
 */
#define OE_WRITE_VALUE_WITH_BARRIER(dest, value)                \
    do                                                          \
    {                                                           \
        uint16_t _ds;                                           \
        asm volatile("movw %%ds, %0\n\t"                        \
                     "verw %0\n\t"                              \
                     "mov %2, %1\n\t"                           \
                     "mfence\n\t"                               \
                     "lfence\n\t"                               \
                     : "=m"(_ds), "=m"(*(typeof(value)*)(dest)) \
                     : "r"(value)                               \
                     : "cc");                                   \
    } while (0)

OE_EXTERNC_END

#endif /* _OE_BITS_SGX_WRITEBARRIER_H */
