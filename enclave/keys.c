// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/enclave.h>
#include "asmdefs.h"

/* The EGETKEY wrapper. */
uint64_t _OE_EGetKey(const Sgx_KeyRequest* sgxKeyRequest, Sgx_Key* sgxKey);

/*
 * The get key implementation that requests the key from processor and convert 
 * the error code.
 */
static OE_Result GetKeyImp(
    const Sgx_KeyRequest* sgxKeyRequest,
    Sgx_Key* sgxKey)
{
    OE_Result ret;
    uint64_t egetkey_result;
    OE_ALIGNED(SGX_KEY_REQUEST_ALIGNMENT) Sgx_KeyRequest tmp_key_request;
    OE_ALIGNED(SGX_KEY_ALIGNMENT) Sgx_Key tmp_sgx_key;

    // Copy input parameter into local aligned buffers.
    OE_Memcpy(&tmp_key_request, sgxKeyRequest, sizeof(Sgx_KeyRequest));

    // Execute EGETKEY instruction.
    egetkey_result = _OE_EGetKey(&tmp_key_request, &tmp_sgx_key);

    // Convert the EGETKEY result to OE_Result.
    switch (egetkey_result)
    {
    case SGX_SUCCESS:
        ret = OE_OK;
        break;

    case SGX_INVALID_ATTRIBUTE:
        ret = OE_INVALID_PARAMETER;
        break;

    case SGX_INVALID_CPUSVN:
        ret = OE_INVALID_CPUSVN;
        break;

    case SGX_INVALID_ISVSVN:
        ret = OE_INVALID_ISVSVN;
        break;

    case SGX_INVALID_KEYNAME:
        ret = OE_INVALID_KEYNAME;
        break;

    default:
        ret = OE_UNEXPECTED;
        break;
    }

    // Copy the request key to output buffer, and clear it from stack.
    if (ret == OE_OK)
    {
        OE_Memcpy(sgxKey, &tmp_sgx_key, sizeof(Sgx_Key));
        OE_Memset(&tmp_sgx_key, 0, sizeof(Sgx_Key));
    }

    return ret;
}

/**
 * Get a secret SGX key.
 *
 * Call this function to get a secret SGX key from processor.
 *
 * @param sgxKeyRequest The parameter points to the KEYQUEST structure that
 * describes which key and how it should be derived. This parameter must point
 * to a readable memory block inside enclave.
 * @param sgxKey The parameter points to Sgx_Key structure where the key will be
 * returned. This parameter must point to a writable memory block inside 
 * enclave.
 *
 * @returns This function returns an OE_OK and the requested key is written to 
 *  sgxKey if success, otherwise the sgxKey will be not changed and return 
 *  following errors:
 *  OE_INVALID_PARAMETER - invalid parameter.
 *  OE_INVALID_CPUSVN - invalid CPUSVN in key request.
 *  OE_INVALID_ISVSVN - invalid ISVSVN in key request.
 *  OE_INVALID_KEYNAME - invalid KEYNAME in key request.
 *  OE_UNEXPECTED - unexpected error.
 *  
 */
OE_Result OE_GetKey(const Sgx_KeyRequest* sgxKeyRequest, Sgx_Key* sgxKey)
{
    // Check the input parameters.
    // Key request and key must be inside enclave.
    if ((sgxKeyRequest == NULL) ||
        !OE_IsWithinEnclave(sgxKeyRequest, sizeof(Sgx_KeyRequest)))
    {
        return OE_INVALID_PARAMETER;
    }

    if ((sgxKey == NULL) ||
        !OE_IsWithinEnclave(sgxKey, sizeof(Sgx_Key)))
    {
        return OE_INVALID_PARAMETER;
    }

    // Reserved fields inside key request must be all zero.
    if (sgxKeyRequest->reserved1 != 0)
    {
        return OE_INVALID_PARAMETER;
    }

    for (uint32_t i = 0; i < OE_COUNTOF(sgxKeyRequest->reserved2); i++)
    {
        if (sgxKeyRequest->reserved2[i] != 0)
        {
            return OE_INVALID_PARAMETER;
        }
    }

    // Key name must be valid.
    if ((sgxKeyRequest->key_name < SGX_KEYSELECT_EINITTOKEN) ||
        (sgxKeyRequest->key_name > SGX_KEYSELECT_SEAL))
    {
        return OE_INVALID_PARAMETER;
    }

    // Reserved fields of key policy must be all zero.
    if (sgxKeyRequest->key_policy & ~(SGX_KEYPOLICY_ALL))
    {
        return OE_INVALID_PARAMETER;
    }

    return GetKeyImp(sgxKeyRequest, sgxKey);
}