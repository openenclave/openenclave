// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _TYPES_H
#define _TYPES_H

#include <stdio.h>

#ifdef BUILD_ENCLAVE
typedef struct _FILE FILE;
#endif

typedef struct UndefinedStruct UndefinedStructTag;

struct DefinedStruct
{
    int arr[1024];
};

#endif /*  _TYPES_H */
