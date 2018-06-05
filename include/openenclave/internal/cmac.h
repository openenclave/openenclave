// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CMAC_H
#define _OE_CMAC_H

#include <openenclave/result.h>
#include <openenclave/types.h>
#include "sgxtypes.h"
#include "utils.h"

OE_EXTERNC_BEGIN

/* Opaque representation of an AES-CMAC */
typedef struct _OE_AESCMAC
{
    /* Internal implementation */
    uint64_t impl[4];
} OE_AESCMAC;

/**
 * OE_SecureAESCMACEqual does a secure constant time comparison of two
 * OE_AESCMAC instances. Returns 1 if equal and 0 otherwise.
 */
OE_INLINE uint8_t
OE_SecureAESCMACEqual(const OE_AESCMAC* a, const OE_AESCMAC* b)
{
    return OE_ConstantTimeMemEqual(a, b, sizeof(*a)) ? 1 : 0;
}

/**
 * OE_AESCMACSign computes the AES-CMAC for the given message using the
 * specified key.
 *
 * @param key The key used to compute the AES-CMAC.
 * @param keySize The size of the key in bytes.
 * @param message Pointer to start of the message.
 * @param messageLength Length of the message in bytes.
 *
 * @param cmac Output parameter where the computed AES-CMAC will be written to.
 */
OE_Result OE_AESCMACSign(
    const uint8_t* key,
    uint32_t keySize,
    const uint8_t* message,
    uint32_t messageLength,
    OE_AESCMAC* aesCMAC);

OE_EXTERNC_END

#endif /* _OE_CMAC_H */
