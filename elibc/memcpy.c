// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>

void* memcpy(void* dest, const void* src, size_t n)
{
    return oe_memcpy(dest, src, n);
}
