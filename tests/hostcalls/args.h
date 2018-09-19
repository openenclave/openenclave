// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _HOSTCALLS_ARGS_H
#define _HOSTCALLS_ARGS_H

#define TEST_HOSTREALLOC_INIT_VALUE 'X'

typedef struct _TestHostMallocArgs
{
    size_t inSize;
    void* outPtr;
} TestHostMallocArgs;

typedef struct _TestHostCallocArgs
{
    size_t inNum;
    size_t inSize;
    void* outPtr;
} TestHostCallocArgs;

typedef struct _TestHostReallocArgs
{
    void* inPtr;
    size_t oldSize;
    size_t newSize;
    void* outPtr;
} TestHostReallocArgs;

typedef struct _TestHostStrndupArgs
{
    const char* inStr;
    size_t inSize;
    char* outStr;
} TestHostStrndupArgs;

#endif /* _HOSTCALLS_ARGS_H */
