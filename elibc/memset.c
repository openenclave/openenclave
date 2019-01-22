// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>

void* memset(void* s, int c, size_t n)
{
    return oe_memset(s, c, n);
}
