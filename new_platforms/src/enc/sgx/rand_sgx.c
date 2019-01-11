/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <openenclave/enclave.h>
#include <sgx_trts.h>
#include "oeresult.h"

oe_result_t oe_random(void* data, size_t size)
{
    sgx_status_t sgxStatus = sgx_read_rand((unsigned char *)data, size);
    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    return oeResult;
}
