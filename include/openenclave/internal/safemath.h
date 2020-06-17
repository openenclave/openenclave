// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SAFEMATH_H
#define _OE_SAFEMATH_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

/*
 * This header provides safe arithmetic functions for adding, subtracting
 * and multiplying 8/16/32/64 bit signed/unsigned integers. These functions
 * return `OE_INTEGER_OVERFLOW` if overflow is detected and `OE_OK` otherwise.
 * Also, these functions will use GCC/Clang's `__builtin_*_overflow` intrinsics
 * if they are available.
 */

OE_EXTERNC_BEGIN

/* Disable GCC warnings for -Wtype-limits. */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#pragma GCC diagnostic ignored "-Wconversion"
#endif /* __GNUC__ */

/* Some compilers don't have __has_builtin like MSVC. */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif /* __has_builtin */

#if __has_builtin(__builtin_add_overflow)
#define SAFE_ADD(a, b, c, minz, maxz) \
    return __builtin_add_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#else
/*
 * Two cases for addition:
 * - (b > 0): a + b overflows if a + b > MAX, so check a > MAX - b.
 * - (b < 0): a + b overflows if a + b < MIN, so check a < MIN - b.
 * Note that the unsigned case is handled by the (b > 0) case.
 */
#define SAFE_ADD(a, b, c, minz, maxz)      \
    do                                     \
    {                                      \
        if ((b) > 0 && (a) > (maxz) - (b)) \
            return OE_INTEGER_OVERFLOW;    \
        if ((b) < 0 && (a) < (minz) - (b)) \
            return OE_INTEGER_OVERFLOW;    \
        *(c) = (a) + (b);                  \
        return OE_OK;                      \
    } while (0);
#endif /* __has_builtin(__builtin_add_overflow) */

#if __has_builtin(__builtin_sub_overflow)
#define SAFE_SUBTRACT(a, b, c, minz, maxz) \
    return __builtin_sub_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#else
/*
 * Two cases for subtraction:
 * - (b > 0): a - b overflows if a - b < MIN, so check a < MIN + b.
 * - (b < 0): a - b overflows if a - b > MAX, so check a > MAX + b.
 * Note that the unsigned case is handled by the (b > 0) case with MIN = 0.
 */
#define SAFE_SUBTRACT(a, b, c, minz, maxz) \
    do                                     \
    {                                      \
        if ((b) > 0 && (a) < (minz) + (b)) \
            return OE_INTEGER_OVERFLOW;    \
        if ((b) < 0 && (a) > (maxz) + (b)) \
            return OE_INTEGER_OVERFLOW;    \
        *(c) = (a) - (b);                  \
        return OE_OK;                      \
    } while (0);
#endif /* __has_builtin(__builtin_sub_overflow) */

#if __has_builtin(__builtin_mul_overflow)
#define SAFE_MULTIPLY(a, b, c, minz, maxz) \
    return __builtin_mul_overflow(a, b, c) ? OE_INTEGER_OVERFLOW : OE_OK;
#else
/*
 * Four cases for multiply:
 * - (a > 0, b > 0): a * b overflows if a * b > MAX, so check a > MAX / b.
 * - (a > 0, b < 0): a * b overflows if a * b < MIN, so check b < MIN / a.
 * - (a < 0, b > 0): a * b overflows if a * b < MIN, so check a < MIN / b.
 * - (a < 0, b < 0): a * b overflows if a * b > MAX, so check a < MAX / b.
 * Note that the unsigned case is handled by the (a > 0, b > 0) case.
 *
 * For the (a > 0, b < 0) case, we purposely do MIN / a instead of
 * MIN / b, since MIN / b produces an integer overflow if b == -1.
 */
#define SAFE_MULTIPLY(a, b, c, minz, maxz)  \
    do                                      \
    {                                       \
        if ((a) > 0 && (b) > 0)             \
        {                                   \
            if ((a) > (maxz) / (b))         \
                return OE_INTEGER_OVERFLOW; \
        }                                   \
        else if ((a) > 0 && (b) < 0)        \
        {                                   \
            if ((b) < (minz) / (a))         \
                return OE_INTEGER_OVERFLOW; \
        }                                   \
        else if ((a) < 0 && (b) > 0)        \
        {                                   \
            if ((a) < (minz) / (b))         \
                return OE_INTEGER_OVERFLOW; \
        }                                   \
        else if ((a) < 0 && (b) < 0)        \
        {                                   \
            if ((a) < (maxz) / (b))         \
                return OE_INTEGER_OVERFLOW; \
        }                                   \
        *(c) = (a) * (b);                   \
        return OE_OK;                       \
    } while (0);
#endif /* __has_builtin(__builtin_mul_overflow) */

/* Safe addition methods. */
OE_INLINE oe_result_t oe_safe_add_s8(int8_t a, int8_t b, int8_t* c)
{
    SAFE_ADD(a, b, c, OE_INT8_MIN, OE_INT8_MAX);
}

OE_INLINE oe_result_t oe_safe_add_u8(uint8_t a, uint8_t b, uint8_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_UINT8_MAX);
}

OE_INLINE oe_result_t oe_safe_add_s16(int16_t a, int16_t b, int16_t* c)
{
    SAFE_ADD(a, b, c, OE_INT16_MIN, OE_INT16_MAX);
}

OE_INLINE oe_result_t oe_safe_add_u16(uint16_t a, uint16_t b, uint16_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_UINT16_MAX);
}

OE_INLINE oe_result_t oe_safe_add_s32(int32_t a, int32_t b, int32_t* c)
{
    SAFE_ADD(a, b, c, OE_INT32_MIN, OE_INT32_MAX);
}

OE_INLINE oe_result_t oe_safe_add_u32(uint32_t a, uint32_t b, uint32_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_UINT32_MAX);
}

OE_INLINE oe_result_t oe_safe_add_s64(int64_t a, int64_t b, int64_t* c)
{
    SAFE_ADD(a, b, c, OE_INT64_MIN, OE_INT64_MAX);
}

OE_INLINE oe_result_t oe_safe_add_u64(uint64_t a, uint64_t b, uint64_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_UINT64_MAX);
}

OE_INLINE oe_result_t oe_safe_add_sizet(size_t a, size_t b, size_t* c)
{
    SAFE_ADD(a, b, c, 0, OE_SIZE_MAX);
}

/* Safe subtraction methods. */
OE_INLINE oe_result_t oe_safe_sub_s8(int8_t a, int8_t b, int8_t* c)
{
    SAFE_SUBTRACT(a, b, c, OE_INT8_MIN, OE_INT8_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_u8(uint8_t a, uint8_t b, uint8_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_UINT8_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_s16(int16_t a, int16_t b, int16_t* c)
{
    SAFE_SUBTRACT(a, b, c, OE_INT16_MIN, OE_INT16_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_u16(uint16_t a, uint16_t b, uint16_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_UINT16_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_s32(int32_t a, int32_t b, int32_t* c)
{
    SAFE_SUBTRACT(a, b, c, OE_INT32_MIN, OE_INT32_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_u32(uint32_t a, uint32_t b, uint32_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_UINT32_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_s64(int64_t a, int64_t b, int64_t* c)
{
    SAFE_SUBTRACT(a, b, c, OE_INT64_MIN, OE_INT64_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_u64(uint64_t a, uint64_t b, uint64_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_UINT64_MAX);
}

OE_INLINE oe_result_t oe_safe_sub_sizet(size_t a, size_t b, size_t* c)
{
    SAFE_SUBTRACT(a, b, c, 0, OE_SIZE_MAX);
}

/* Safe multiplication methods. */
OE_INLINE oe_result_t oe_safe_mul_s8(int8_t a, int8_t b, int8_t* c)
{
    SAFE_MULTIPLY(a, b, c, OE_INT8_MIN, OE_INT8_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_u8(uint8_t a, uint8_t b, uint8_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_UINT8_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_s16(int16_t a, int16_t b, int16_t* c)
{
    SAFE_MULTIPLY(a, b, c, OE_INT16_MIN, OE_INT16_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_u16(uint16_t a, uint16_t b, uint16_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_UINT16_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_s32(int32_t a, int32_t b, int32_t* c)
{
    SAFE_MULTIPLY(a, b, c, OE_INT32_MIN, OE_INT32_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_u32(uint32_t a, uint32_t b, uint32_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_UINT32_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_s64(int64_t a, int64_t b, int64_t* c)
{
    SAFE_MULTIPLY(a, b, c, OE_INT64_MIN, OE_INT64_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_u64(uint64_t a, uint64_t b, uint64_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_UINT64_MAX);
}

OE_INLINE oe_result_t oe_safe_mul_sizet(size_t a, size_t b, size_t* c)
{
    SAFE_MULTIPLY(a, b, c, 0, OE_SIZE_MAX);
}

/* Re-enable GCC warnings for -Wtype-limits. */
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif /* __GNUC__ */

OE_EXTERNC_END

#endif /* _OE_SAFEMATH_H */
