// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _HOSTCALLS_ARGS_H
#define _HOSTCALLS_ARGS_H

#define TEST_HOSTREALLOC_INIT_VALUE 'X'

typedef struct _test_host_realloc_args
{
    void* inPtr;
    size_t oldSize;
    size_t newSize;
    void* outPtr;
} TestHostReallocArgs;

#endif /* _HOSTCALLS_ARGS_H */
