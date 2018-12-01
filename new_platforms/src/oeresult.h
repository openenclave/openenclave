/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#include <sgx.h>
#include <openenclave/bits/result.h>

#ifdef OE_USE_OPTEE
# error oeresult.h should only be included for SGX compilation
#endif

oe_result_t GetOEResultFromSgxStatus(sgx_status_t status);
sgx_status_t GetSgxStatusFromOEResult(oe_result_t result);
