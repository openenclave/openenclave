// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * \file properties.h
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

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

/* Injected by OE_SET_ENCLAVE_SGX macro and by the signing tool (oesign) */
#define OE_INFO_SECTION_NAME ".oeinfo"

/*
**==============================================================================
**
** OE_EnclavePropertiesHeader - generic enclave properties base type
**
**==============================================================================
*/

typedef enum _OE_EnclaveType { OE_ENCLAVE_TYPE_SGX } OE_EnclaveType;

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
    /* (0) Size of the extended structure */
    uint32_t size;

    /* (4) Type of enclave (see OE_EnclaveType) */
    uint32_t enclaveType;

    /* (8) Type of enclave */
    OE_EnclaveSizeSettings sizeSettings;
} OE_EnclavePropertiesHeader;

OE_CHECK_SIZE(sizeof(OE_EnclavePropertiesHeader), 32);

/*
**==============================================================================
**
** OE_EnclaveProperties_SGX - SGX enclave properties derived type
**
**==============================================================================
*/

#define OE_SGX_FLAGS_DEBUG 0x0000000000000002ULL
#define OE_SGX_FLAGS_MODE64BIT 0x0000000000000004ULL

typedef struct _OE_EnclaveSettings_SGX
{
    uint16_t productID;
    uint16_t securityVersion;

    /* Padding to make packed and unpacked size the same */
    uint32_t padding;

    /* (SGX_FLAGS_DEBUG | SGX_FLAGS_MODE64BIT) */
    uint64_t attributes;
} OE_EnclaveSettings_SGX;

OE_CHECK_SIZE(sizeof(OE_EnclaveSettings_SGX), 16);

/* Extends OE_EnclavePropertiesHeader base type */
typedef struct _OE_EnclaveProperties_SGX
{
    /* (0) */
    OE_EnclavePropertiesHeader header;

    /* (32) */
    OE_EnclaveSettings_SGX settings;

    /* (48) */
    uint8_t sigstruct[1808];
} OE_EnclaveProperties_SGX;

OE_CHECK_SIZE(sizeof(OE_EnclaveProperties_SGX), 1856);

/*
**==============================================================================
**
** OE_SET_ENCLAVE_SGX:
**     This macro initializes and injects an OE_EnclaveProperties_SGX struct
**     into the .oeinfo section.
**
**==============================================================================
*/

#define OE_INFO_SECTION_BEGIN __attribute__((section(".oeinfo,\"\",@note#")))
#define OE_INFO_SECTION_END

#define OE_MAKE_ATTRIBUTES(_AllowDebug_) \
    (OE_SGX_FLAGS_MODE64BIT | (_AllowDebug_ ? OE_SGX_FLAGS_DEBUG : 0))

// Note: disable clang-format since it badly misformats this macro
// clang-format off

#define OE_SET_ENCLAVE_SGX(                                             \
    _ProductID_,                                                        \
    _SecurityVersion_,                                                  \
    _AllowDebug_,                                                       \
    _HeapPageCount_,                                                    \
    _StackPageCount_,                                                   \
    _TcsCount_)                                                         \
    OE_INFO_SECTION_BEGIN                                               \
    OE_EXPORT const OE_EnclaveProperties_SGX oe_enclavePropertiesSGX =  \
    {                                                                   \
        .header =                                                       \
        {                                                               \
            .size = sizeof(OE_EnclaveProperties_SGX),                   \
            .enclaveType = OE_ENCLAVE_TYPE_SGX,                         \
            .sizeSettings =                                             \
            {                                                           \
                .numHeapPages = _HeapPageCount_,                        \
                .numStackPages = _StackPageCount_,                      \
                .numTCS = _TcsCount_                                    \
            }                                                           \
        },                                                              \
        .settings =                                                     \
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
