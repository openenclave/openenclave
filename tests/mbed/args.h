// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#include <stddef.h>

typedef struct _Args
{
    const void* data;
    size_t size;
    unsigned char hash[32];
} Args;

#endif /* _ARGS_H */
