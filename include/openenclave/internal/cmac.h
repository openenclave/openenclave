// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CMAC_H
#define _OE_CMAC_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
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
 * oe_secure_aes_cmac_equal does a secure constant time comparison of two
 * OE_AESCMAC instances. Returns 1 if equal and 0 otherwise.
 */
OE_INLINE uint8_t
oe_secure_aes_cmac_equal(const OE_AESCMAC* a, const OE_AESCMAC* b)
{
    return oe_constant_time_mem_equal(a, b, sizeof(*a)) ? 1 : 0;
}

/**
 * oe_aes_cmac_sign computes the AES-CMAC for the given message using the
 * specified key.
 *
 * @param key The key used to compute the AES-CMAC.
 * @param keySize The size of the key in bytes.
 * @param message Pointer to start of the message.
 * @param messageLength Length of the message in bytes.
 *
 * @param cmac Output parameter where the computed AES-CMAC will be written to.
 */
oe_result_t oe_aes_cmac_sign(
    const uint8_t* key,
    size_t keySize,
    const uint8_t* message,
    size_t messageLength,
    OE_AESCMAC* aesCMAC);

OE_EXTERNC_END

#endif /* _OE_CMAC_H */
