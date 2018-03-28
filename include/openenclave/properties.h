// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * \file properties.h
 *
 * This file defines enclave-property structures that are injected into
 * the ".oeinfo" section (either by a macro or by the signing tool).
 *
 * Note: the field sizes were carefully selected so that the packed
 * sizes and unpacked sizes are the same.
 *
 */

#ifndef _OE_PROPERTIES_H
#define _OE_PROPERTIES_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE_EnclavePropertiesHeader - generic enclave properties base struct
**
**==============================================================================
*/

typedef enum _OE_EnclaveType
{
    OE_ENCLAVE_TYPE_SGX
}
OE_EnclaveType;

typedef struct _OE_EnclaveSizeSettings 
{
    uint64_t numHeapPages;
    uint64_t numStackPages;
    uint64_t numTCS;
}
OE_EnclaveSizeSettings; 

OE_CHECK_SIZE(sizeof(OE_EnclaveSizeSettings), 24);

/* Base struct type for enclave properties */
typedef struct _OE_EnclavePropertiesHeader 
{
    /* (0) Size of the extended structure */
    uint32_t size; 

    /* (4) Type of enclave (see OE_EnclaveType) */
    uint32_t enclaveType; 

    /* (8) Type of enclave */
    OE_EnclaveSizeSettings sizeSettings; 
}
OE_EnclavePropertiesHeader; 

OE_CHECK_SIZE(sizeof(OE_EnclavePropertiesHeader), 32);

/*
**==============================================================================
**
** OE_EnclaveProperties_SGX - SGX enclave properties derived struct
**
**==============================================================================
*/

#define OE_SGXKEY_SIZE 384
#define OE_SGXEXPONENT_SIZE 4
#define OE_HASH_SIZE 32

typedef struct _OE_SGXAttributes
{
    uint64_t flags;
    uint64_t xfrm;
} OE_SGXAttributes;

OE_CHECK_SIZE(sizeof(OE_SGXAttributes), 16);

typedef struct _OE_SGXSigStruct
{
    /* ======== HEADER-SECTION ======== */

    /* (0) must be (06000000E100000000000100H) */
    uint8_t header[12];

    /* (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero */
    uint32_t type;

    /* (16) Intel=0x8086, ISV=0x0000 */
    uint32_t vendor;

    /* (20) build date as yyyymmdd */
    uint32_t date;

    /* (24) must be (01010000600000006000000001000000H) */
    uint8_t header2[16];

    /* (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0 */
    uint32_t swdefined;

    /* (44) Must be 0 */
    uint8_t reserved[84];

    /* ======== KEY-SECTION ======== */

    /* (128) Module Public Key (keylength=3072 bits) */
    uint8_t modulus[OE_SGXKEY_SIZE];

    /* (512) RSA Exponent = 3 */
    uint8_t exponent[OE_SGXEXPONENT_SIZE];

    /* (516) Signature over Header and Body (HEADER-SECTION | BODY-SECTION) */
    uint8_t signature[OE_SGXKEY_SIZE];

    /* ======== BODY-SECTION ======== */

    /* (900) The MISCSELECT that must be set */
    uint32_t miscselect;

    /* (904) Mask of MISCSELECT to enforce */
    uint32_t miscmask;

    /* (908) Reserved. Must be 0. */
    uint8_t reserved2[20];

    /* (928) Enclave Attributes that must be set */
    OE_SGXAttributes attributes;

    /* (944) Mask of Attributes to Enforce */
    OE_SGXAttributes attributemask;

    /* (960) MRENCLAVE - (32 bytes) */
    uint8_t enclavehash[OE_HASH_SIZE];

    /* (992) Must be 0 */
    uint8_t reserved3[32];

    /* (1024) ISV assigned Product ID */
    uint16_t isvprodid;

    /* (1026) ISV assigned SVN */
    uint16_t isvsvn;

    /* ======== BUFFER-SECTION ======== */

    /* (1028) Must be 0 */
    uint8_t reserved4[12];

    /* (1040) Q1 value for RSA Signature Verification */
    uint8_t q1[OE_SGXKEY_SIZE];

    /* (1424) Q2 value for RSA Signature Verification */
    uint8_t q2[OE_SGXKEY_SIZE];
} OE_SGXSigStruct;

OE_CHECK_SIZE(sizeof(OE_SGXSigStruct), 1808);

typedef struct _OE_SGX_EnclaveSettings
{ 
    uint16_t productID; 
    uint16_t securityVersion; 
    uint32_t padding; 
    uint64_t attributes; 
}
OE_SGXEnclaveSettings; 

OE_CHECK_SIZE(sizeof(OE_SGXEnclaveSettings), 16);

/* extends OE_EnclavePropertiesHeader */
typedef struct _OE_EnclaveProperties_SGX 
{ 
    /* (0) */
    OE_EnclavePropertiesHeader header; 

    /* (32) */
    OE_SGXEnclaveSettings settings; 

    /* (48) */
    OE_SGXSigStruct sigstruct; 
}
OE_EnclaveProperties_SGX;

OE_CHECK_SIZE(sizeof(OE_EnclaveProperties_SGX), 1856);

OE_EXTERNC_END

#endif /* _OE_PROPERTIES_H */
