// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SHA_H
#define _OE_SHA_H

#include "../defs.h"
#include "../result.h"
#include "../types.h"

OE_EXTERNC_BEGIN

#define OE_SHA256_SIZE 32

typedef struct _OE_SHA256Context
{
    uint64_t impl[16];
} OE_SHA256Context;

typedef struct _OE_SHA256
{
    unsigned char buf[OE_SHA256_SIZE];
} OE_SHA256;

OE_Result OE_SHA256Init(OE_SHA256Context* context);

OE_Result OE_SHA256Update(
    OE_SHA256Context* context,
    const void* data,
    size_t size);

OE_Result OE_SHA256Final(OE_SHA256Context* context, OE_SHA256* sha256);

OE_EXTERNC_END

#endif /* _OE_SHA_H */
