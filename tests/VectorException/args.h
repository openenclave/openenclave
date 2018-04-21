// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H
#include <openenclave/bits/cpuid.h>

typedef struct _TestVectorExceptionArgs
{
    int ret;
} TestVectorExceptionArgs;

typedef struct _TestSigillHandlingArgs
{
    int ret;
    uint32_t cpuidTable[OE_CPUID_LEAF_COUNT][OE_CPUID_REG_COUNT];
} TestSigillHandlingArgs;

#endif /* _ARGS_H */
