// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/globals.h>
#include <openenclave/enclave.h>

bool OE_IsWithinEnclave(const void* p, size_t n)
{
    uint64_t rangeStart = (uint64_t)p;
    uint64_t rangeEnd = rangeStart + (n == 0 ? 1 : n);
    uint64_t enclaveStart = (uint64_t)__OE_GetEnclaveBase();
    uint64_t enclaveEnd = enclaveStart + __OE_GetEnclaveSize();

    // Disallow nullptr and check that arithmetic operations do not wrap
    // Check that block lies completely within the enclave
    if ((rangeStart > 0) && (rangeEnd > rangeStart) &&
        (enclaveEnd > enclaveStart) &&
        ((rangeStart >= enclaveStart) && (rangeEnd <= enclaveEnd)))
    {
        return true;
    }

    return false;
}

bool OE_IsOutsideEnclave(const void* p, size_t n)
{
    uint64_t rangeStart = (uint64_t)p;
    uint64_t rangeEnd = rangeStart + (n == 0 ? 1 : n);
    uint64_t enclaveStart = (uint64_t)__OE_GetEnclaveBase();
    uint64_t enclaveEnd = enclaveStart + __OE_GetEnclaveSize();

    // Disallow nullptr and check that arithmetic operations do not wrap
    // Check that block lies completely outside the enclave
    if ((rangeStart > 0) && (rangeEnd > rangeStart) &&
        (enclaveEnd > enclaveStart) &&
        ((rangeEnd <= enclaveStart) || (rangeStart >= enclaveEnd)))
    {
        return true;
    }

    return false;
}
