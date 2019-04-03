// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#ifndef _OE_BITS_TYPES_H
#define _OE_BITS_TYPES_H

#include "defs.h"

#if 1

typedef void (*oe_call_t)(
    void* inBuffer,
    size_t inBufferSize,
    void* outBuffer,
    size_t outBufferSize,
    size_t* outBufferSizeWritten);

#else

/* Basic types */
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
#define OE_LONG_MAX 0x7fffffffffffffffL
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

#endif

/**
 * This enumeration defines values for the **enclave_type** parameter
 * passed to **oe_create_enclave()**.
 */
typedef enum _oe_enclave_type
{
    OE_ENCLAVE_TYPE_UNDEFINED,
    OE_ENCLAVE_TYPE_SGX,
    OE_ENCLAVE_TYPE_TRUSTZONE,
    __OE_ENCLAVE_TYPE_MAX = OE_ENUM_MAX,
} oe_enclave_type_t;

/**
 * This is an opaque handle to an enclave returned by oe_create_enclave().
 * This definition is shared by the enclave and the host.
 */
typedef struct _oe_enclave oe_enclave_t;

/**
 * This enumeration type defines the policy used to derive a seal key.
 */
typedef enum _oe_seal_policy {
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
/**< typedef enum _oe_seal_policy oe_seal_policy_t*/

#endif /* _OE_BITS_TYPES_H */
