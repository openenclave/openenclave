// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ocall_args_h
#define _ocall_args_h

#include <openenclave/internal/calls.h>
#include <openenclave/internal/sgxtypes.h>

#define TEST1_MAGIC 0xec9a613e

typedef struct _Test1Args
{
    void* self;

    /* --- Input arguments --- */

    int64_t inNum;

    const char* inStr;

    /* --- Output arguments --- */

    int64_t op;
    unsigned int magic;

    char* str;

    volatile void* sp1;
    volatile void* sp2;
    volatile void* sp3;

    unsigned int* mem;

    void* func;

    int ret;
} Test1Args;

typedef struct _Test2Args
{
    int64_t in;
    int64_t out;
} Test2Args;

typedef struct _TestAllocatorArgs
{
    int ret;
} TestAllocatorArgs;

typedef struct _Func1Args
{
    char buf[128];
} Func1Args;

typedef struct _SetTSDArgs
{
    void* value;
    int ret;
} SetTSDArgs;

typedef struct _GetTSDArgs
{
    void* value;
    int ret;
} GetTSDArgs;

typedef struct _TestMyOCallArgs
{
    uint64_t result;
} TestMyOCallArgs;

typedef struct _my_ocall_args
{
    uint64_t in;
    uint64_t out;
}
my_ocall_args_t;

#endif /* _ocall_args_h */
