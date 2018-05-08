// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ECDSA_H
#define _OE_ECDSA_H

#include "../result.h"
#include "../types.h"

OE_EXTERNC_BEGIN

typedef struct _OE_ECDSA256Key
{
    uint8_t x[32];
    uint8_t y[32];
} OE_ECDSA256Key;

typedef struct _OE_ECDSA256Signature
{
    uint8_t r[32];
    uint8_t s[32];
} OE_ECDSA256Signature;

OE_Result OE_ECDSA256_SHA_Verify(
    const OE_ECDSA256Key* key,
    const void* data,
    uint32_t size,
    const OE_ECDSA256Signature* signautre);

OE_EXTERNC_END

#endif // _OE_ECDSA_H
