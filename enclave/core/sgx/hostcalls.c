// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "internal_t.h"

void* oe_host_realloc(void* ptr, size_t size)
{
    void* retval = NULL;

    if (!ptr)
        return oe_host_malloc(size);

    if (oe_realloc_ocall(&retval, ptr, size) != OE_OK)
        return NULL;

    return retval;
}

int oe_host_write(int device, const char* str, size_t len)
{
    if (oe_write_ocall(device, str, len) != OE_OK)
        return -1;

    return 0;
}
