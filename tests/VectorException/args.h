// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _vectorException_args_h
#define _vectorException_args_h
#include <openenclave/bits/cpuid.h>

typedef struct _TestVectorExceptionArgs
{
    int ret;
} TestVectorExceptionArgs;

typedef struct _TestSigillHandlingArgs
{
    int ret;
    uint32_t cpuidTable[OE_CPUID_LEAF_COUNT][OE_CPUID_REG_COUNT];
    uint32_t r1;
    uint32_t r2;
} TestSigillHandlingArgs;

#endif /* _ARGS_H */
