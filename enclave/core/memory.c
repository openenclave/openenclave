// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/globals.h>
#include <openenclave/enclave.h>

bool OE_IsWithinEnclave(const void* p, size_t n)
{
    const uint8_t* start = (const uint8_t*)p;
    const uint8_t* end = (const uint8_t*)p + n;
    const uint8_t* base = (const uint8_t*)__OE_GetEnclaveBase();
    uint64_t size = __OE_GetEnclaveSize();

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

bool OE_IsOutsideEnclave(const void* p, size_t n)
{
    const uint8_t* start = (const uint8_t*)p;
    const uint8_t* end = (const uint8_t*)p + n;
    const uint8_t* base = (const uint8_t*)__OE_GetEnclaveBase();
    uint64_t size = __OE_GetEnclaveSize();

    // Postcondition tests to verify that wrapping didn't occur
    if (end < start)
    {
        return false;
    }

    if (base + size < base)
    {
        return false;
    }

    // Case 1 - Start is within the enclave region
    if (!(start < base || start >= (base + size)))
        return false;

    if (n)
    {
        end--;
        // Case 2 - Range end is within the enclave (at base or beyond but
        // within the enclave)
        if (!(end < base || end >= (base + size)))
            return false;
    }

    // Case 3 - Range starts at/before the enclave starts and ends at/beyond the
    // enclave
    if ((start <= base) && end >= (base + size))
    {
        return false;
    }

    return true;
}
