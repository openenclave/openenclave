// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>

bool oe_is_within_enclave(const void* p, size_t n)
{
    uint64_t range_start = (uint64_t)p;
    uint64_t range_end = range_start + (n == 0 ? 1 : n);
    uint64_t enclave_start = (uint64_t)__oe_get_enclave_base();
    uint64_t enclave_end = enclave_start + __oe_get_enclave_size();

    // Disallow nullptr and check that arithmetic operations do not wrap
    // Check that block lies completely within the enclave
    if ((range_start > 0) && (range_end > range_start) &&
        (enclave_end > enclave_start) &&
        ((range_start >= enclave_start) && (range_end <= enclave_end)))
    {
        return true;
    }

    return false;
}

bool oe_is_outside_enclave(const void* p, size_t n)
{
    uint64_t range_start = (uint64_t)p;
    uint64_t range_end = range_start + (n == 0 ? 1 : n);
    uint64_t enclave_start = (uint64_t)__oe_get_enclave_base();
    uint64_t enclave_end = enclave_start + __oe_get_enclave_size();

    // Disallow nullptr and check that arithmetic operations do not wrap
    // Check that block lies completely outside the enclave
    if ((range_start > 0) && (range_end > range_start) &&
        (enclave_end > enclave_start) &&
        ((range_end <= enclave_start) || (range_start >= enclave_end)))
    {
        return true;
    }

    return false;
}
