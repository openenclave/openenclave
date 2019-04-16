// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/random.h>
#include <stddef.h>
#include "sgx_error.h"

sgx_status_t sgx_read_rand(unsigned char* rand, size_t length_in_bytes)
{
    if (!rand || !length_in_bytes)
        return SGX_ERROR_INVALID_PARAMETER;

    if (!oe_is_within_enclave(rand, length_in_bytes) &&
        !oe_is_outside_enclave(rand, length_in_bytes))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (oe_random_internal(rand, length_in_bytes) != OE_OK)
    {
        return SGX_ERROR_UNEXPECTED;
    }

    return 0;
}
