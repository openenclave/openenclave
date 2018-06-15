// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file properties.h
 *
 * This file defines the SGX properties for an enclave.
 *
 * The enclave properties should only be defined once for all code compiled
 * into an enclave binary using the OE_SET_ENCLAVE_SGX macro.
 * These properties can be overwritten at sign time by the oesign tool.
 */

#ifndef _OE_BITS_PROPERTIES_H
#define _OE_BITS_PROPERTIES_H

#include "defs.h"
#include "types.h"

OE_EXTERNC_BEGIN

/**
 * @cond DEV
 */
/* Injected by OE_SET_ENCLAVE_SGX macro and by the signing tool (oesign) */
#define OE_INFO_SECTION_NAME ".oeinfo"

/* Max number of threads in an enclave supported */
#define OE_SGX_MAX_TCS 32

typedef struct _oe_enclave_size_settings
{
    uint64_t numHeapPages;
    uint64_t numStackPages;
    uint64_t numTCS;
} oe_enclave_size_settings_t;

OE_CHECK_SIZE(sizeof(oe_enclave_size_settings_t), 24);

/* Base type for enclave properties */
typedef struct _oe_enclave_properties_header
{
    uint32_t size; /**< (0) Size of the extended structure */

    oe_enclave_type_t enclaveType; /**< (4) Enclave type */

    oe_enclave_size_settings_t sizeSettings; /**< (8) Enclave settings */
} oe_enclave_properties_header_t;

OE_STATIC_ASSERT(sizeof(oe_enclave_type_t) == sizeof(uint32_t));
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_properties_header_t, size) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_properties_header_t, enclaveType) == 4);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_enclave_properties_header_t, sizeSettings) == 8);
OE_CHECK_SIZE(sizeof(oe_enclave_properties_header_t), 32);

// oe_sgx_enclave_properties_t SGX enclave properties derived type
#define OE_SGX_FLAGS_DEBUG 0x0000000000000002ULL
#define OE_SGX_FLAGS_MODE64BIT 0x0000000000000004ULL
#define OE_SGX_SIGSTRUCT_SIZE 1808

typedef struct oe_sgx_enclave_config_t
{
    uint16_t productID;
    uint16_t securityVersion;

    /* Padding to make packed and unpacked size the same */
    uint32_t padding;

    /* (OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT) */
    uint64_t attributes;
} oe_sgx_enclave_config_t;

OE_CHECK_SIZE(sizeof(oe_sgx_enclave_config_t), 16);

/* Extends oe_enclave_properties_header_t base type */
typedef struct oe_sgx_enclave_properties_t
{
    /* (0) */
    oe_enclave_properties_header_t header;

    /* (32) */
    oe_sgx_enclave_config_t config;

    /* (48) */
    uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE];
} oe_sgx_enclave_properties_t;

OE_CHECK_SIZE(sizeof(oe_sgx_enclave_properties_t), 1856);

#define OE_INFO_SECTION_BEGIN __attribute__((section(".oeinfo,\"\",@note#")))
#define OE_INFO_SECTION_END

#define OE_MAKE_ATTRIBUTES(_allow_debug_) \
    (OE_SGX_FLAGS_MODE64BIT | (_allow_debug_ ? OE_SGX_FLAGS_DEBUG : 0))

/**
 * @endcond
 */

// This macro initializes and injects an oe_sgx_enclave_properties_t struct
// into the .oeinfo section.

/**
 * Defines the SGX properties for an enclave.
 *
 * The enclave properties should only be defined once for all code compiled into
 * an enclave binary. These properties can be overwritten at sign time by
 * the oesign tool.
 *
 * @param \_product_id\_ ISV assigned Product ID (ISVPRODID) to use in the
 * enclave signature
 * @param \_security_version\_ ISV assigned Security Version number (ISVSVN)
 * to use in the enclave signature
 * @param \_allow_debug\_ If true, allows the enclave to be created with
 * OE_ENCLAVE_FLAG_DEBUG and debugged at runtime
 * @param \_heap_page_count\_ Number of heap pages to allocate in the enclave
 * @param \_stack_page_count\_ Number of stack pages per thread to reserve in
 * the enclave
 * @param \_tcs_count\_ Number of concurrent threads in an enclave to support
 */
// Note: disable clang-format since it badly misformats this macro
// clang-format off

#define OE_SET_ENCLAVE_SGX(                                             \
    _product_id_,                                                        \
    _security_version_,                                                  \
    _allow_debug_,                                                       \
    _heap_page_count_,                                                    \
    _stack_page_count_,                                                   \
    _tcs_count_)                                                         \
    OE_INFO_SECTION_BEGIN                                               \
    OE_EXPORT const oe_sgx_enclave_properties_t oe_enclavePropertiesSGX =  \
    {                                                                   \
        .header =                                                       \
        {                                                               \
            .size = sizeof(oe_sgx_enclave_properties_t),                   \
            .enclaveType = OE_ENCLAVE_TYPE_SGX,                         \
            .sizeSettings =                                             \
            {                                                           \
                .numHeapPages = _heap_page_count_,                        \
                .numStackPages = _stack_page_count_,                      \
                .numTCS = _tcs_count_                                    \
            }                                                           \
        },                                                              \
        .config =                                                       \
        {                                                               \
            .productID = _product_id_,                                   \
            .securityVersion = _security_version_,                       \
            .padding = 0,                                               \
            .attributes = OE_MAKE_ATTRIBUTES(_allow_debug_)              \
        },                                                              \
        .sigstruct =                                                    \
        {                                                               \
            0                                                           \
        }                                                               \
    };                                                                  \
    OE_INFO_SECTION_END

// clang-format on

OE_EXTERNC_END

#endif /* _OE_BITS_PROPERTIES_H */
