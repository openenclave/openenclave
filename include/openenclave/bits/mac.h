// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_MAC_H
#define _OE_MAC_H

#include "../result.h"
#include "../types.h"
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

typedef struct _OE_MAC
{
    uint8_t bytes[SGX_MAC_SIZE];
} OE_MAC;

OE_Result OE_GetMAC(
    const uint8_t* sealKey,
    uint32_t sealKeySize,
    const uint8_t* src,
    uint32_t len,
    OE_MAC* mac);

OE_EXTERNC_END

#endif /* _OE_MAC_H */
