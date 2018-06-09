// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/globals.h>
#include <openenclave/enclave.h>

bool oe_is_within_enclave(const void* p, size_t n)
{
    const uint8_t* start = (const uint8_t*)p;
    const uint8_t* end = (const uint8_t*)p + n;
    const uint8_t* base = (const uint8_t*)__oe_get_enclave_base();
    uint64_t size = __oe_get_enclave_size();

    if (!(start >= base && start < (base + size)))
        return false;

    if (n)
    {
        end--;

        if (!(end >= base && end < (base + size)))
            return false;
    }

    return true;
}

bool oe_is_outside_enclave(const void* p, size_t n)
{
    const uint8_t* start = (const uint8_t*)p;
    const uint8_t* end = (const uint8_t*)p + n;
    const uint8_t* base = (const uint8_t*)__oe_get_enclave_base();
    uint64_t size = __oe_get_enclave_size();

    if (!(start < base || start >= (base + size)))
        return false;

    if (n)
    {
        end--;

        if (!(end < base || end >= (base + size)))
            return false;
    }

    return true;
}
