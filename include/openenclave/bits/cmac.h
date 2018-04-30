// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CMAC_H
#define _OE_CMAC_H

#include "../result.h"
#include "../types.h"
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

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
    uint8_t* cmac);

OE_EXTERNC_END

#endif /* _OE_CMAC_H */
