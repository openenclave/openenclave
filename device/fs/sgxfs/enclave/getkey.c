// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/keys.h>
#include <openenclave/internal/sgxtypes.h>
#include "sgx_error.h"

sgx_status_t sgx_get_key(const sgx_key_request_t* key_request, sgx_key_t* key)
{
    if (!key_request || !key)
        return SGX_ERROR_INVALID_PARAMETER;

    if (oe_get_key(key_request, key) != OE_OK)
        return SGX_ERROR_UNEXPECTED;

    return 0;
}
