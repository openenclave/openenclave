// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _HOSTCALLS_ARGS_H
#define _HOSTCALLS_ARGS_H

#define TEST_HOSTREALLOC_INIT_VALUE 'X'

typedef struct _test_host_malloc_args
{
    size_t in_size;
    void* out_ptr;
} TestHostMallocArgs;

typedef struct _test_host_calloc_args
{
    size_t in_num;
    size_t in_size;
    void* out_ptr;
} TestHostCallocArgs;

typedef struct _test_host_realloc_args
{
    void* in_ptr;
    size_t old_size;
    size_t new_size;
    void* out_ptr;
} TestHostReallocArgs;

typedef struct _test_host_strndup_args
{
    const char* in_str;
    size_t in_size;
    char* out_str;
} TestHostStrndupArgs;

#endif /* _HOSTCALLS_ARGS_H */
