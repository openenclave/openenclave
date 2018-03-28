// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * \file properties.h
 *
 * This file defines enclave-property structures that are injected into
 * the ".oeinfo" section (either by a macro or by the signing tool).
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

typedef struct _OE_EnclavePropertiesHeader 
{ 
    uint32_t size; 
    OE_EnclaveType type; 
    OE_EnclaveSizeSettings sizeSettings; 
} 
OE_EnclavePropertiesHeader; 

/*
**==============================================================================
**
** OE_EnclaveProperties_SGX - SGX enclave properties derived struct
**
**==============================================================================
*/

#define OE_SGX_KEY_SIZE 384
#define OE_SGX_EXPONENT_SIZE 4
#define OE_HASH_SIZE 32

OE_PACK_BEGIN
typedef struct _SGX_Attributes
{
    uint64_t flags;
    uint64_t xfrm;
} SGX_Attributes;
OE_PACK_END

OE_CHECK_SIZE(sizeof(SGX_Attributes), 16);

OE_PACK_BEGIN
typedef struct _SGX_SigStruct
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
    uint8_t modulus[OE_SGX_KEY_SIZE];

    /* (512) RSA Exponent = 3 */
    uint8_t exponent[OE_SGX_EXPONENT_SIZE];

    /* (516) Signature over Header and Body (HEADER-SECTION | BODY-SECTION) */
    uint8_t signature[OE_SGX_KEY_SIZE];

    /* ======== BODY-SECTION ======== */

    /* (900) The MISCSELECT that must be set */
    uint32_t miscselect;

    /* (904) Mask of MISCSELECT to enforce */
    uint32_t miscmask;

    /* (908) Reserved. Must be 0. */
    uint8_t reserved2[20];

    /* (928) Enclave Attributes that must be set */
    SGX_Attributes attributes;

    /* (944) Mask of Attributes to Enforce */
    SGX_Attributes attributemask;

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
    uint8_t q1[OE_SGX_KEY_SIZE];

    /* (1424) Q2 value for RSA Signature Verification */
    uint8_t q2[OE_SGX_KEY_SIZE];
} SGX_SigStruct;
OE_PACK_END

OE_CHECK_SIZE(sizeof(SGX_SigStruct), 1808);


typedef struct _SGX_EnclaveProperties
{ 
    uint16_t productID; 
    uint16_t securityVersion; 
    uint64_t attributes; 
} 
SGX_EnclaveProperties; 

/* extends OE_EnclavePropertiesHeader */
typedef struct _OE_EnclaveProperties_SGX 
{ 
    OE_EnclavePropertiesHeader header; 
    SGX_EnclaveProperties settings; 
    SGX_SigStruct sigstruct; 
} 
OE_EnclaveProperties_SGX;

OE_EXTERNC_END

#endif /* _OE_PROPERTIES_H */
