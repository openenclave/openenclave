// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#include <stddef.h>

typedef struct _HashArgs
{
    const void* data;
    size_t size;
    unsigned char hash[32];
} HashArgs;

typedef struct _AesArgs
{
    uint8_t plaintext[128];
    uint8_t encrypted[128];
} AesArgs;

#endif /* _ARGS_H */
