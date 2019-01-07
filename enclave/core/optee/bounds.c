// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/enclave.h>

bool oe_is_within_enclave(const void* ptr, size_t sz)
{
    OE_UNUSED(ptr);
    OE_UNUSED(sz);
    return true;
}

bool oe_is_outside_enclave(const void* ptr, size_t sz)
{
    OE_UNUSED(ptr);
    OE_UNUSED(sz);
    return false;
}
