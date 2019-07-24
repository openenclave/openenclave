// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

void* oe_host_realloc(void* ptr, size_t size)
{
    OE_UNUSED(ptr);
    OE_UNUSED(size);

    return NULL;
}

int oe_host_write(int device, const char* str, size_t len)
{
    OE_UNUSED(device);
    OE_UNUSED(str);
    OE_UNUSED(len);

    return -1;
}
