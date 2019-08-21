// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/entropy.h>

oe_result_t oe_get_entropy(void* output, size_t len)
{
    OE_UNUSED(output);
    OE_UNUSED(len);

    return OE_UNSUPPORTED;
}
