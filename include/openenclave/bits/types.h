// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file types.h
 *
 * This file defines the types used by the OE SDK.
 */

#ifndef _OE_BITS_TYPES_H
#define _OE_BITS_TYPES_H

#include "defs.h"

/**
 * @cond DEV
 *
 * Basic types
 */
#if defined(__GNUC__)
typedef long ssize_t;
typedef unsigned long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef long ptrdiff_t;
typedef long intptr_t;
typedef long time_t;
typedef long suseconds_t;

#ifndef __cplusplus
typedef __WCHAR_TYPE__ wchar_t;
#endif

#elif defined(_MSC_VER)
typedef long long ssize_t;
typedef unsigned long long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long long uintptr_t;
typedef long long ptrdiff_t;
typedef long long intptr_t;
typedef long long time_t;
typedef long long suseconds_t;
#else
#error "unknown compiler - please adapt basic types"
#endif

/* bool type */
#ifndef __cplusplus
#define true 1
#define false 0
#define bool _Bool
#endif

#define OE_SCHAR_MIN (-128)
#define OE_SCHAR_MAX 127
#define OE_UCHAR_MAX 255
#define OE_CHAR_MIN (-128)
#define OE_CHAR_MAX 127
#define OE_CHAR_BIT 8
#define OE_SHRT_MIN (-1 - 0x7fff)
#define OE_SHRT_MAX 0x7fff
#define OE_USHRT_MAX 0xffff
#define OE_INT_MIN (-1 - 0x7fffffff)
#define OE_INT_MAX 0x7fffffff
#define OE_UINT_MAX 0xffffffffU

#ifdef _MSC_VER
#define OE_LONG_MAX 0x7fffffffL
#elif __linux__
#define OE_LONG_MAX 0x7fffffffffffffffL
#endif

#define OE_LONG_MIN (-OE_LONG_MAX - 1)
#define OE_ULONG_MAX (2UL * OE_LONG_MAX + 1)
#define OE_LLONG_MAX 0x7fffffffffffffffLL
#define OE_LLONG_MIN (-OE_LLONG_MAX - 1)
#define OE_ULLONG_MAX (2ULL * OE_LLONG_MAX + 1)

#define OE_INT8_MIN (-1 - 0x7f)
#define OE_INT8_MAX (0x7f)
#define OE_UINT8_MAX (0xff)
#define OE_INT16_MIN (-1 - 0x7fff)
#define OE_INT16_MAX (0x7fff)
#define OE_UINT16_MAX (0xffff)
#define OE_INT32_MIN (-1 - 0x7fffffff)
#define OE_INT32_MAX (0x7fffffff)
#define OE_UINT32_MAX (0xffffffffu)
#define OE_INT64_MIN (-1 - 0x7fffffffffffffff)
#define OE_INT64_MAX (0x7fffffffffffffff)
#define OE_UINT64_MAX (0xffffffffffffffffu)
#define OE_SIZE_MAX OE_UINT64_MAX
#define OE_SSIZE_MAX OE_INT64_MAX
/**
 * @endcond
 */

/**
 * This enumeration defines values for the type parameter
 * passed to **oe_create_enclave()**.
 */
typedef enum _oe_enclave_type
{
    /**
     * OE_ENCLAVE_TYPE_AUTO will pick the type
     * based on the target platform that is being built, such that x64 binaries
     * will use SGX.
     */
    OE_ENCLAVE_TYPE_AUTO = 1,
    /**
     * OE_ENCLAVE_TYPE_SGX will force the platform to use SGX, but any platform
     * other than x64 will not support this and will generate errors.
     */
    OE_ENCLAVE_TYPE_SGX = 2,
    /**
     * OE_ENCLAVE_TYPE_OPTEE will force the platform to use OP-TEE, but any
     * platform other than one that implements ARM TrustZone with OP-TEE as its
     * secure kernel will not support this and will generate errors.
     */
    OE_ENCLAVE_TYPE_OPTEE = 3,
    /**
     * Unused
     */
    __OE_ENCLAVE_TYPE_MAX = OE_ENUM_MAX,
} oe_enclave_type_t;

/**
 * This is an opaque handle to an enclave returned by oe_create_enclave().
 * This definition is shared by the enclave and the host.
 */
typedef struct _oe_enclave oe_enclave_t;

/**
 * This enumeration type defines the policy used to derive a seal key.
 * This definition is shared by the enclave and the host.
 */
typedef enum _oe_seal_policy
{
    /**
     * Key is derived from a measurement of the enclave. Under this policy,
     * the sealed secret can only be unsealed by an instance of the exact
     * enclave code that sealed it.
     */
    OE_SEAL_POLICY_UNIQUE = 1,
    /**
     * Key is derived from the signer of the enclave. Under this policy,
     * the sealed secret can be unsealed by any enclave signed by the same
     * signer as that of the sealing enclave.
     */
    OE_SEAL_POLICY_PRODUCT = 2,
    /**
     * Unused.
     */
    _OE_SEAL_POLICY_MAX = OE_ENUM_MAX,
} oe_seal_policy_t;

/**
 * This struct defines a datetime up to 1 second precision.
 */
typedef struct _oe_datetime
{
    uint32_t year;    /* format: 1970, 2018, 2020 */
    uint32_t month;   /* range: 1-12 */
    uint32_t day;     /* range: 1-31 */
    uint32_t hours;   /* range: 0-23 */
    uint32_t minutes; /* range: 0-59 */
    uint32_t seconds; /* range: 0-59 */
} oe_datetime_t;

#endif /* _OE_BITS_TYPES_H */
