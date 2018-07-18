// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#define USE_DL_PREFIX
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include "../3rdparty/dlmalloc/dlmalloc/malloc.h"

/* Stubs needed to compile the libcxxrt library */

int __libcxxrt_dladdr(void* addr, Dl_info* info)
{
    assert("__libcxxrt_dladdr(): panic" == NULL);
    return -1;
}

int __libcxxrt_sched_yield(void)
{
    assert("__libcxxrt_sched_yield(): panic" == NULL);
    return -1;
}

void* __libcxxrt_malloc(size_t size)
{
    return dlmalloc(size);
}

void __libcxxrt_free(void* ptr)
{
    return dlfree(ptr);
}

void* __libcxxrt_calloc(size_t nmemb, size_t size)
{
    return dlcalloc(nmemb, size);
}

void* __libcxxrt_realloc(void* ptr, size_t size)
{
    return dlrealloc(ptr, size);
}
