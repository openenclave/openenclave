// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file properties.h
 *
 * This file defines enclave-property structures which are injected into
 * the following sections of the enclave image.
 *
 *     .oeinfo - injected by OE_SET_ENCLAVE_SGX (contains
 *               enclave properties with empty sigstructs)
 *
 */

#ifndef _OE_PROPERTIES_H
#define _OE_PROPERTIES_H

#include "defs.h"
#include "types.h"

OE_EXTERNC_BEGIN

/**
 * @cond DUMMY
 */
/* Injected by OE_SET_ENCLAVE_SGX macro and by the signing tool (oesign) */
#define OE_INFO_SECTION_NAME ".oeinfo"

/* Max number of threads in an enclave supported */
#define OE_SGX_MAX_TCS 32

typedef struct _OE_EnclaveSizeSettings
{
    uint64_t numHeapPages;
    uint64_t numStackPages;
    uint64_t numTCS;
} OE_EnclaveSizeSettings;

OE_CHECK_SIZE(sizeof(OE_EnclaveSizeSettings), 24);

/* Base type for enclave properties */
typedef struct _OE_EnclavePropertiesHeader
{
    uint32_t size; /**< (0) Size of the extended structure */

    OE_EnclaveType enclaveType; /**< (4) Enclave type */

    OE_EnclaveSizeSettings sizeSettings; /**< (8) Enclave settings */
} OE_EnclavePropertiesHeader;

OE_STATIC_ASSERT(sizeof(OE_EnclaveType) == sizeof(uint32_t));
OE_STATIC_ASSERT(OE_OFFSETOF(OE_EnclavePropertiesHeader, size) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(OE_EnclavePropertiesHeader, enclaveType) == 4);
OE_STATIC_ASSERT(OE_OFFSETOF(OE_EnclavePropertiesHeader, sizeSettings) == 8);
OE_CHECK_SIZE(sizeof(OE_EnclavePropertiesHeader), 32);

// OE_SGXEnclaveProperties SGX enclave properties derived type
#define OE_SGX_FLAGS_DEBUG 0x0000000000000002ULL
#define OE_SGX_FLAGS_MODE64BIT 0x0000000000000004ULL
#define OE_SGX_SIGSTRUCT_SIZE 1808

typedef struct OE_SGXEnclaveConfig
{
    uint16_t productID;
    uint16_t securityVersion;

    /* Padding to make packed and unpacked size the same */
    uint32_t padding;

    /* (OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT) */
    uint64_t attributes;
} OE_SGXEnclaveConfig;

OE_CHECK_SIZE(sizeof(OE_SGXEnclaveConfig), 16);

/* Extends OE_EnclavePropertiesHeader base type */
typedef struct OE_SGXEnclaveProperties
{
    /* (0) */
    OE_EnclavePropertiesHeader header;

    /* (32) */
    OE_SGXEnclaveConfig config;

    /* (48) */
    uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE];
} OE_SGXEnclaveProperties;

OE_CHECK_SIZE(sizeof(OE_SGXEnclaveProperties), 1856);

#define OE_INFO_SECTION_BEGIN __attribute__((section(".oeinfo,\"\",@note#")))
#define OE_INFO_SECTION_END

#define OE_MAKE_ATTRIBUTES(_AllowDebug_) \
    (OE_SGX_FLAGS_MODE64BIT | (_AllowDebug_ ? OE_SGX_FLAGS_DEBUG : 0))

/**
 * @endcond
 */

// Note: disable clang-format since it badly misformats this macro
// clang-format off
/**
 * This macro is used to set the enclave.
 *
 * This macro initializes and injects an OE_SGXEnclaveProperties struct
 * into the .oeinfo section.
 *
 * @param \_ProductID\_ ISV assigned Product ID (ISVPRODID) to be used in the enclave signature 
 * @param \_SecurityVersion\_ ISV assigned Security Version number (ISVSVN) to be used in the enclave signature 
 * @param \_AllowDebug\_ If 1, the enclave permits debugger to read/write data to enclave
 * @param \_HeapPageCount\_ Number of heap pages
 * @param \_StackPageCount\_ Number of stack pages dedicated to the thread context
 * @param \_TcsCount\_ Number of Thread Control Structures
 */
#define OE_SET_ENCLAVE_SGX(                                             \
    _ProductID_,                                                        \
    _SecurityVersion_,                                                  \
    _AllowDebug_,                                                       \
    _HeapPageCount_,                                                    \
    _StackPageCount_,                                                   \
    _TcsCount_)                                                         \
    OE_INFO_SECTION_BEGIN                                               \
    OE_EXPORT const OE_SGXEnclaveProperties oe_enclavePropertiesSGX =  \
    {                                                                   \
        .header =                                                       \
        {                                                               \
            .size = sizeof(OE_SGXEnclaveProperties),                   \
            .enclaveType = OE_ENCLAVE_TYPE_SGX,                         \
            .sizeSettings =                                             \
            {                                                           \
                .numHeapPages = _HeapPageCount_,                        \
                .numStackPages = _StackPageCount_,                      \
                .numTCS = _TcsCount_                                    \
            }                                                           \
        },                                                              \
        .config =                                                       \
        {                                                               \
            .productID = _ProductID_,                                   \
            .securityVersion = _SecurityVersion_,                       \
            .padding = 0,                                               \
            .attributes = OE_MAKE_ATTRIBUTES(_AllowDebug_)              \
        },                                                              \
        .sigstruct =                                                    \
        {                                                               \
            0                                                           \
        }                                                               \
    };                                                                  \
    OE_INFO_SECTION_END

// clang-format on

OE_EXTERNC_END

#endif /* _OE_PROPERTIES_H */
