// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <openenclave/enclave.h>
#include <stdlib.h>

int dladdr(const void* addr, Dl_info* info)
{
    OE_UNUSED(addr);
    OE_UNUSED(info);
    assert("dladdr(): panic" == NULL);
    return -1;
}
