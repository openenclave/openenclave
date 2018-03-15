// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SHA_H
#define _OE_SHA_H

#include "../defs.h"
#include "../result.h"
#include "../types.h"

OE_EXTERNC_BEGIN

#define OE_SHA256_SIZE 32

#define OE_SHA256_STRING_SIZE ((OE_SHA256_SIZE)*2 + 1)

#define OE_SHA256_INIT \
    {                  \
        {              \
            0          \
        }              \
    }

typedef struct _OE_SHA256Context
{
    uint64_t impl[16];
} OE_SHA256Context;

typedef struct _OE_SHA256
{
    unsigned char buf[OE_SHA256_SIZE];
} OE_SHA256;

typedef struct _OE_SHA256Str
{
    char buf[OE_SHA256_STRING_SIZE];
} OE_SHA256Str;

void OE_SHA256Init(OE_SHA256Context* context);

void OE_SHA256Update(OE_SHA256Context* context, const void* data, size_t size);

void OE_SHA256UpdateZeros(OE_SHA256Context* context, size_t size);

void OE_SHA256Final(OE_SHA256Context* context, OE_SHA256* sha256);

void OE_SHA256ToStr(const OE_SHA256* sha256, OE_SHA256Str* str);

OE_SHA256Str OE_SHA256StrOf(const OE_SHA256* sha256);

OE_SHA256Str OE_SHA256StrOfContext(const OE_SHA256Context* context);

OE_EXTERNC_END

#endif /* _OE_SHA_H */
