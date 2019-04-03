// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <stdlib.h>

int dladdr(const void* addr, Dl_info* info)
{
    (void)(addr);
    (void)(info);
    assert("dladdr(): panic" == NULL);
    return -1;
}
