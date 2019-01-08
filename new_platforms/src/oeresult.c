/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifndef _MSC_VER
#include "sal_unsup.h"
#endif

#include <stddef.h>

#include <openenclave/bits/result.h>
#include <sgx.h>

oe_result_t GetOEResultFromSgxStatus(sgx_status_t status)
{
    switch (status) {
    case SGX_SUCCESS:                     return OE_OK;
    case SGX_ERROR_UNEXPECTED:            return OE_UNEXPECTED;
    case SGX_ERROR_INVALID_PARAMETER:     return OE_INVALID_PARAMETER;
    case SGX_ERROR_OUT_OF_MEMORY:         return OE_OUT_OF_MEMORY;
    case SGX_ERROR_FEATURE_NOT_SUPPORTED: return OE_UNSUPPORTED;
    case SGX_ERROR_SERVICE_UNAVAILABLE:   return OE_SERVICE_UNAVAILABLE;
    case SGX_ERROR_INVALID_CPUSVN:        return OE_INVALID_CPUSVN;
    case SGX_ERROR_INVALID_ISVSVN:        return OE_INVALID_ISVSVN;
    case SGX_ERROR_INVALID_KEYNAME:       return OE_INVALID_KEYNAME;
    case SGX_ERROR_BUSY:                  return OE_BUSY;
    case SGX_ERROR_ENCLAVE_FILE_ACCESS:   return OE_NOT_FOUND;
    default:                              return OE_FAILURE;
    }
}

sgx_status_t GetSgxStatusFromOEResult(oe_result_t result)
{
    switch (result) {
    case OE_OK:                          return SGX_SUCCESS;
    case OE_UNEXPECTED:                  return SGX_ERROR_UNEXPECTED;
    case OE_INVALID_PARAMETER:           return SGX_ERROR_INVALID_PARAMETER;
    case OE_OUT_OF_MEMORY:               return SGX_ERROR_OUT_OF_MEMORY;
    case OE_UNSUPPORTED:                 return SGX_ERROR_FEATURE_NOT_SUPPORTED;
    case OE_SERVICE_UNAVAILABLE:         return SGX_ERROR_SERVICE_UNAVAILABLE;
    case OE_INVALID_CPUSVN:              return SGX_ERROR_INVALID_CPUSVN;
    case OE_INVALID_ISVSVN:              return SGX_ERROR_INVALID_ISVSVN;
    case OE_INVALID_KEYNAME:             return SGX_ERROR_INVALID_KEYNAME;
    case OE_BUSY:                        return SGX_ERROR_BUSY;
    default:                             return SGX_ERROR_UNEXPECTED;
    }
}
