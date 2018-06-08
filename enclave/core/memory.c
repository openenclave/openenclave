// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/globals.h>
#include <openenclave/enclave.h>

bool OE_IsWithinEnclave(const void* p, size_t n)
{
    const uint8_t* rangeStart = (const uint8_t*)p;
    const uint8_t* rangeEnd = (const uint8_t*)p + n;

    const uint8_t* enclaveBase = (const uint8_t*)__OE_GetEnclaveBase();
    uint64_t enclaveSize = __OE_GetEnclaveSize();
    const uint8_t* enclaveEnd = enclaveBase + enclaveSize;

    // Check that arithmetic operations do not wrap
    if (rangeEnd < rangeStart || enclaveEnd < enclaveBase)
        return false;

    // Block must lie completely within the enclave
    return (rangeStart >= enclaveBase && rangeEnd <= enclaveEnd);
}

bool OE_IsOutsideEnclave(const void* p, size_t n)
{
    const uint8_t* rangeStart = (const uint8_t*)p;
    const uint8_t* rangeEnd = (const uint8_t*)p + n;

    const uint8_t* enclaveBase = (const uint8_t*)__OE_GetEnclaveBase();
    uint64_t enclaveSize = __OE_GetEnclaveSize();
    const uint8_t* enclaveEnd = enclaveBase + enclaveSize;

    // Check that arithmetic operations do not wrap.
    if (rangeEnd < rangeStart || enclaveEnd < enclaveBase)
        return false;

    // Block must lie completely outside the enclave.
    // It can lie fully to the left or fully to the right.
    // ......................|enclaveBase....enclaveEnd|......................
    //  rangeStart ..rangeEnd|              or         |rangeStart....rangeEnd
    return (rangeEnd <= enclaveBase || rangeStart >= enclaveEnd);
}
