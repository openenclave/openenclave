// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/sgxtypes.h>
#include "asmdefs.h"
#include "report.h"

OE_STATIC_ASSERT(sizeof(oe_seal_policy_t) == sizeof(unsigned int));

/* The EGETKEY wrapper. */
uint64_t oe_egetkey(const sgx_key_request_t* sgxKeyRequest, sgx_key_t* sgxKey);

/*
 * The get key implementation that requests the key from processor and convert
 * the error code.
 */
static oe_result_t _GetKeyImp(
    const sgx_key_request_t* sgxKeyRequest,
    sgx_key_t* sgxKey)
{
    oe_result_t ret;
    uint64_t egetkeyResult;
    OE_ALIGNED(SGX_KEY_REQUEST_ALIGNMENT) sgx_key_request_t tmpKeyRequest;
    OE_ALIGNED(SGX_KEY_ALIGNMENT) sgx_key_t tmpSgxKey;

    // Copy input parameter into local aligned buffers.
    oe_memcpy(&tmpKeyRequest, sgxKeyRequest, sizeof(sgx_key_request_t));

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
        oe_memcpy(sgxKey, &tmpSgxKey, sizeof(sgx_key_t));
        oe_memset(&tmpSgxKey, 0, sizeof(sgx_key_t));
    }

    return ret;
}

oe_result_t oe_get_key(
    const sgx_key_request_t* sgxKeyRequest,
    sgx_key_t* sgxKey)
{
    // Check the input parameters.
    // Key request and key must be inside enclave.
    if ((sgxKeyRequest == NULL) ||
        !oe_is_within_enclave(sgxKeyRequest, sizeof(sgx_key_request_t)))
    {
        return OE_INVALID_PARAMETER;
    }

    if ((sgxKey == NULL) || !oe_is_within_enclave(sgxKey, sizeof(sgx_key_t)))
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
    size_t keyInfoSize,
    uint8_t* keyBuffer,
    size_t* keyBufferSize)
{
    oe_result_t ret;

    // Check parameters.
    if ((keyInfo == NULL) || (keyInfoSize != sizeof(sgx_key_request_t)))
    {
        return OE_INVALID_PARAMETER;
    }

    if ((keyBuffer == NULL) || (keyBufferSize == NULL))
    {
        return OE_INVALID_PARAMETER;
    }

    if (*keyBufferSize < sizeof(sgx_key_t))
    {
        *keyBufferSize = sizeof(sgx_key_t);
        return OE_BUFFER_TOO_SMALL;
    }

    // Get the key based on input key info.
    ret = oe_get_key((sgx_key_request_t*)keyInfo, (sgx_key_t*)keyBuffer);
    if (ret == OE_OK)
    {
        *keyBufferSize = sizeof(sgx_key_t);
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
static oe_result_t _GetDefaultKeyRequestAttributes(
    sgx_key_request_t* sgxKeyRequest)
{
    sgx_report_t sgxReport = {{{0}}};

    oe_result_t ret;

    // Get a local report of current enclave.
    ret = sgx_create_report(NULL, 0, NULL, 0, &sgxReport);

    if (ret != OE_OK)
    {
        return ret;
    }

    // Set key request attributes(isv svn, cpu svn, and attribute masks)
    sgxKeyRequest->isv_svn = sgxReport.body.isvsvn;
    oe_memcpy(
        &sgxKeyRequest->cpu_svn,
        sgxReport.body.cpusvn,
        OE_FIELD_SIZE(sgx_key_request_t, cpu_svn));
    sgxKeyRequest->attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgxKeyRequest->attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
    sgxKeyRequest->misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;
    return OE_OK;
}

oe_result_t oe_get_seal_key_by_policy(
    oe_seal_policy_t sealPolicy,
    uint8_t* keyBuffer,
    size_t* keyBufferSize,
    uint8_t* keyInfo,
    size_t* keyInfoSize)
{
    oe_result_t ret;
    sgx_key_request_t sgxKeyRequest = {0};

    // Check parameters.
    if (keyBuffer == NULL || keyBufferSize == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    // Key buffer size must be big enough.
    if (*keyBufferSize < sizeof(sgx_key_t))
    {
        *keyBufferSize = sizeof(sgx_key_t);
        return OE_BUFFER_TOO_SMALL;
    }

    // Key info size must be big enough if request key info.
    if ((keyInfo != NULL) && (*keyInfoSize < sizeof(sgx_key_request_t)))
    {
        *keyInfoSize = sizeof(sgx_key_request_t);
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
        case OE_SEAL_POLICY_UNIQUE:
            sgxKeyRequest.key_policy = SGX_KEYPOLICY_MRENCLAVE;
            break;

        case OE_SEAL_POLICY_PRODUCT:
            sgxKeyRequest.key_policy = SGX_KEYPOLICY_MRSIGNER;
            break;

        default:
            return OE_INVALID_PARAMETER;
    }

    // Get the seal key.
    ret = oe_get_key(&sgxKeyRequest, (sgx_key_t*)keyBuffer);
    if (ret == OE_OK)
    {
        *keyBufferSize = sizeof(sgx_key_t);

        if (keyInfo != NULL)
        {
            oe_memcpy(keyInfo, &sgxKeyRequest, sizeof(sgx_key_request_t));
            *keyInfoSize = sizeof(sgx_key_request_t);
        }
    }
    else
    {
        // oe_get_key should not fail unless we set the key request wrong.
        ret = OE_UNEXPECTED;
    }

    return ret;
}
