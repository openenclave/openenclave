// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h>

int dladdr(const void *addr, Dl_info *info)
{
    assert("dladdr(): panic" == NULL);
    return -1;
}
