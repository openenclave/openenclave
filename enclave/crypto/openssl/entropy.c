// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include "../../core/platform_t.h"

/**
 * Declare the prototype of the following function to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_sgx_get_additional_host_entropy_ocall(
    oe_result_t* result,
    uint8_t* data,
    size_t size);

oe_result_t _oe_sgx_get_additional_host_entropy_ocall(
    oe_result_t* result,
    uint8_t* data,
    size_t size)
{
    OE_UNUSED(result);
    OE_UNUSED(data);
    OE_UNUSED(size);
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_sgx_get_additional_host_entropy_ocall,
    oe_sgx_get_additional_host_entropy_ocall);

OE_EXPORT
int oe_sgx_get_additional_host_entropy(uint8_t* data, size_t size)
{
    oe_result_t result = OE_FAILURE;

    if (!data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_sgx_get_additional_host_entropy_ocall(&result, data, size));
    OE_CHECK(result);

    result = OE_OK;

done:
    if (result == OE_UNSUPPORTED)
    {
        OE_TRACE_ERROR(
            "oe_sgx_get_additional_host_entropy is not available. To "
            "enable, please add \n\n"
            "from \"openenclave/edl/sgx/entropy.edl\" import *;\n\n"
            "in the edl file.\n");
        oe_abort();
    }

    return result == OE_OK ? 1 : 0;
}
