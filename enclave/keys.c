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
static OE_Result GetKeyImp(const Sgx_KeyRequest* sgxKeyRequest, Sgx_Key* sgxKey)
{
    OE_Result ret;
    uint64_t egetkeyResult;
    OE_ALIGNED(SGX_KEY_REQUEST_ALIGNMENT) Sgx_KeyRequest tmpKeyRequest;
    OE_ALIGNED(SGX_KEY_ALIGNMENT) Sgx_Key tmpSgxKey;

    // Copy input parameter into local aligned buffers.
    OE_Memcpy(&tmpKeyRequest, sgxKeyRequest, sizeof(Sgx_KeyRequest));

    // Execute EGETKEY instruction.
    egetkeyResult = _OE_EGetKey(&tmpKeyRequest, &tmpSgxKey);

    // Convert the EGETKEY result to OE_Result.
    switch (egetkeyResult)
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
        OE_Memcpy(sgxKey, &tmpSgxKey, sizeof(Sgx_Key));
        OE_Memset(&tmpSgxKey, 0, sizeof(Sgx_Key));
    }

    return ret;
}

OE_Result OE_GetKey(const Sgx_KeyRequest* sgxKeyRequest, Sgx_Key* sgxKey)
{
    // Check the input parameters.
    // Key request and key must be inside enclave.
    if ((sgxKeyRequest == NULL) ||
        !OE_IsWithinEnclave(sgxKeyRequest, sizeof(Sgx_KeyRequest)))
    {
        return OE_INVALID_PARAMETER;
    }

    if ((sgxKey == NULL) || !OE_IsWithinEnclave(sgxKey, sizeof(Sgx_Key)))
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

OE_Result OE_GetSealKey(
    const uint8_t* keyInfo,
    uint32_t keyInfoSize,
    uint8_t* keyBuffer,
    uint32_t* keyBufferSize)
{
    OE_Result ret;

    // Check parameters.
    if (keyInfoSize != sizeof(Sgx_KeyRequest))
    {
        return OE_INVALID_PARAMETER;
    }

    if (*keyBufferSize < sizeof(Sgx_Key))
    {
        *keyBufferSize = sizeof(Sgx_Key);
        return OE_BUFFER_TOO_SMALL;
    }

    // Get the key based on input key info.
    ret = OE_GetKey((Sgx_KeyRequest*)keyInfo, (Sgx_Key*)keyBuffer);
    if (ret == OE_OK)
    {
        *keyBufferSize = sizeof(Sgx_Key);
    }
    else
    {
        // If OE_GetKey fails, assume the keyInfo is corrupted.
        ret = OE_INVALID_PARAMETER;
    }

    return ret;
}

/*
 * Get default key request attributes.
 * The ISV SVN and CPU SVN are set to value of current enclave.
 * Attribute masks are set to OE default values.
 *
 * Return OE_OK and set attributes of sgxKeyRequest if success.
 * Otherwise return error and sgxKeyRquest is not changed.
 */
static OE_Result GetDefaultKeyRequestAttributes(Sgx_KeyRequest* sgxKeyRequest)
{
    SGX_Report sgxReport = {0};
    uint32_t sgxReportSize = sizeof(SGX_Report);
    OE_Result ret;

    // Get a local report of current enclave.
    ret =
        OE_GetReport(0, NULL, 0, NULL, 0, (uint8_t*)&sgxReport, &sgxReportSize);

    if (ret != OE_OK)
    {
        return ret;
    }

    // Set key request attributes(isv svn, cpu svn, and attribute masks)
    sgxKeyRequest->isv_svn = sgxReport.body.isvsvn;
    OE_Memcpy(&sgxKeyRequest->cpu_svn, sgxReport.body.cpusvn, SGX_CPUSVN_SIZE);
    sgxKeyRequest->flags_attribute_mask = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgxKeyRequest->xfrm_attribute_mask = OE_SEALKEY_DEFAULT_XFRMMASK;
    sgxKeyRequest->misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;
    return OE_OK;
}

OE_Result OE_GetSealKeyByPolicy(
    OE_SEAL_ID_POLICY sealPolicy,
    uint8_t* keyBuffer,
    uint32_t* keyBufferSize,
    uint8_t* keyInfo,
    uint32_t* keyInfoSize)
{
    OE_Result ret;
    Sgx_KeyRequest sgxKeyRequest = {0};

    // Check parameters.
    // Key buffer size must be big enough.
    if (*keyBufferSize < sizeof(Sgx_Key))
    {
        *keyBufferSize = sizeof(Sgx_Key);
        return OE_BUFFER_TOO_SMALL;
    }

    // Key info size must be big enough if request key info.
    if ((keyInfo != NULL) && (*keyInfoSize < sizeof(Sgx_KeyRequest)))
    {
        *keyInfoSize = sizeof(Sgx_KeyRequest);
        return OE_BUFFER_TOO_SMALL;
    }

    // Get default key request attributes.
    ret = GetDefaultKeyRequestAttributes(&sgxKeyRequest);
    if (ret != OE_OK)
    {
        return OE_UNEXPECTED;
    }

    // Set key name and key policy.
    sgxKeyRequest.key_name = SGX_KEYSELECT_SEAL;
    switch (sealPolicy)
    {
        case OE_SEAL_ID_UNIQUE:
            sgxKeyRequest.key_policy = SGX_KEYPOLICY_MRENCLAVE;
            break;

        case OE_SEAL_ID_PRODUCT:
            sgxKeyRequest.key_policy = SGX_KEYPOLICY_MRSIGNER;
            break;

        default:
            return OE_INVALID_PARAMETER;
    }

    // Get the seal key.
    ret = OE_GetKey(&sgxKeyRequest, (Sgx_Key*)keyBuffer);
    if (ret == OE_OK)
    {
        *keyBufferSize = sizeof(Sgx_Key);

        if (keyInfo != NULL)
        {
            OE_Memcpy(keyInfo, &sgxKeyRequest, sizeof(Sgx_KeyRequest));
            *keyInfoSize = sizeof(Sgx_KeyRequest);
        }
    }
    else
    {
        // OE_GetKey should not fail unless we set the key request wrong.
        ret = OE_UNEXPECTED;
    }

    return ret;
}