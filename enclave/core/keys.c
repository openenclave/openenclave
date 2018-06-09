// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/enclave.h>
#include "asmdefs.h"

/* The EGETKEY wrapper. */
uint64_t oe_egetkey(const SGX_KeyRequest* sgxKeyRequest, SGX_Key* sgxKey);

/*
 * The get key implementation that requests the key from processor and convert
 * the error code.
 */
static oe_result_t _GetKeyImp(
    const SGX_KeyRequest* sgxKeyRequest,
    SGX_Key* sgxKey)
{
    oe_result_t ret;
    uint64_t egetkeyResult;
    OE_ALIGNED(SGX_KEY_REQUEST_ALIGNMENT) SGX_KeyRequest tmpKeyRequest;
    OE_ALIGNED(SGX_KEY_ALIGNMENT) SGX_Key tmpSgxKey;

    // Copy input parameter into local aligned buffers.
    oe_memcpy(&tmpKeyRequest, sgxKeyRequest, sizeof(SGX_KeyRequest));

    // Execute EGETKEY instruction.
    egetkeyResult = oe_egetkey(&tmpKeyRequest, &tmpSgxKey);

    // Convert the EGETKEY result to oe_result_t.
    switch (egetkeyResult)
    {
        case SGX_EGETKEY_SUCCESS:
            ret = OE_OK;
            break;

        case SGX_EGETKEY_INVALID_ATTRIBUTE:
            ret = OE_INVALID_PARAMETER;
            break;

        case SGX_EGETKEY_INVALID_CPUSVN:
            ret = OE_INVALID_CPUSVN;
            break;

        case SGX_EGETKEY_INVALID_ISVSVN:
            ret = OE_INVALID_ISVSVN;
            break;

        case SGX_EGETKEY_INVALID_KEYNAME:
            ret = OE_INVALID_KEYNAME;
            break;

        default:
            ret = OE_UNEXPECTED;
            break;
    }

    // Copy the request key to output buffer, and clear it from stack.
    if (ret == OE_OK)
    {
        // The sgx key is the secret, it should not be left on stack. Clean it
        // up to avoid leak by incident.
        oe_memcpy(sgxKey, &tmpSgxKey, sizeof(SGX_Key));
        oe_memset(&tmpSgxKey, 0, sizeof(SGX_Key));
    }

    return ret;
}

oe_result_t oe_get_key(const SGX_KeyRequest* sgxKeyRequest, SGX_Key* sgxKey)
{
    // Check the input parameters.
    // Key request and key must be inside enclave.
    if ((sgxKeyRequest == NULL) ||
        !oe_is_within_enclave(sgxKeyRequest, sizeof(SGX_KeyRequest)))
    {
        return OE_INVALID_PARAMETER;
    }

    if ((sgxKey == NULL) || !oe_is_within_enclave(sgxKey, sizeof(SGX_Key)))
    {
        return OE_INVALID_PARAMETER;
    }

    // Reserved fields inside key request must be all zero.
    if (sgxKeyRequest->reserved1 != 0)
    {
        return OE_INVALID_PARAMETER;
    }

    for (size_t i = 0; i < OE_COUNTOF(sgxKeyRequest->reserved2); i++)
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

    return _GetKeyImp(sgxKeyRequest, sgxKey);
}

oe_result_t oe_get_seal_key(
    const uint8_t* keyInfo,
    uint32_t keyInfoSize,
    uint8_t* keyBuffer,
    uint32_t* keyBufferSize)
{
    oe_result_t ret;

    // Check parameters.
    if ((keyInfo == NULL) || (keyInfoSize != sizeof(SGX_KeyRequest)))
    {
        return OE_INVALID_PARAMETER;
    }

    if ((keyBuffer == NULL) || (keyBufferSize == NULL))
    {
        return OE_INVALID_PARAMETER;
    }

    if (*keyBufferSize < sizeof(SGX_Key))
    {
        *keyBufferSize = sizeof(SGX_Key);
        return OE_BUFFER_TOO_SMALL;
    }

    // Get the key based on input key info.
    ret = oe_get_key((SGX_KeyRequest*)keyInfo, (SGX_Key*)keyBuffer);
    if (ret == OE_OK)
    {
        *keyBufferSize = sizeof(SGX_Key);
    }

    return ret;
}

/*
 * Get default key request attributes.
 * The ISV SVN and CPU SVN are set to value of current enclave.
 * Attribute masks are set to OE default values.
 *
 * Return OE_OK and set attributes of sgxKeyRequest if success.
 * Otherwise return error and sgxKeyRequest is not changed.
 */
static oe_result_t _GetDefaultKeyRequestAttributes(SGX_KeyRequest* sgxKeyRequest)
{
    SGX_Report sgxReport = {0};
    uint32_t sgxReportSize = sizeof(SGX_Report);
    oe_result_t ret;

    // Get a local report of current enclave.
    ret =
        oe_get_report(0, NULL, 0, NULL, 0, (uint8_t*)&sgxReport, &sgxReportSize);

    if (ret != OE_OK)
    {
        return ret;
    }

    // Set key request attributes(isv svn, cpu svn, and attribute masks)
    sgxKeyRequest->isv_svn = sgxReport.body.isvsvn;
    oe_memcpy(
        &sgxKeyRequest->cpu_svn,
        sgxReport.body.cpusvn,
        OE_FIELD_SIZE(SGX_KeyRequest, cpu_svn));
    sgxKeyRequest->attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgxKeyRequest->attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
    sgxKeyRequest->misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;
    return OE_OK;
}

oe_result_t oe_get_seal_key_by_policy(
    oe_seal_id_policy_t sealPolicy,
    uint8_t* keyBuffer,
    uint32_t* keyBufferSize,
    uint8_t* keyInfo,
    uint32_t* keyInfoSize)
{
    oe_result_t ret;
    SGX_KeyRequest sgxKeyRequest = {0};

    // Check parameters.
    if (keyBuffer == NULL || keyBufferSize == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    // Key buffer size must be big enough.
    if (*keyBufferSize < sizeof(SGX_Key))
    {
        *keyBufferSize = sizeof(SGX_Key);
        return OE_BUFFER_TOO_SMALL;
    }

    // Key info size must be big enough if request key info.
    if ((keyInfo != NULL) && (*keyInfoSize < sizeof(SGX_KeyRequest)))
    {
        *keyInfoSize = sizeof(SGX_KeyRequest);
        return OE_BUFFER_TOO_SMALL;
    }

    // Get default key request attributes.
    ret = _GetDefaultKeyRequestAttributes(&sgxKeyRequest);
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
    ret = oe_get_key(&sgxKeyRequest, (SGX_Key*)keyBuffer);
    if (ret == OE_OK)
    {
        *keyBufferSize = sizeof(SGX_Key);

        if (keyInfo != NULL)
        {
            oe_memcpy(keyInfo, &sgxKeyRequest, sizeof(SGX_KeyRequest));
            *keyInfoSize = sizeof(SGX_KeyRequest);
        }
    }
    else
    {
        // oe_get_key should not fail unless we set the key request wrong.
        ret = OE_UNEXPECTED;
    }

    return ret;
}
