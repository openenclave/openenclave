// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>
#include <unistd.h>

void* elibc_sbrk(ptrdiff_t increment)
{
    return oe_sbrk(increment);
}
