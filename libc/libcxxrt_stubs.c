// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#define USE_DL_PREFIX
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>

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
