// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/sgxtypes.h>
#include "asmdefs.h"

/* The EGETKEY wrapper. */
uint64_t oe_egetkey(const sgx_key_request_t* sgx_key_request, sgx_key_t* sgx_key);

/*
 * The get key implementation that requests the key from processor and convert
 * the error code.
 */
static oe_result_t _get_key_imp(
    const sgx_key_request_t* sgx_key_request,
    sgx_key_t* sgx_key)
{
    oe_result_t ret;
    uint64_t egetkey_result;
    OE_ALIGNED(SGX_KEY_REQUEST_ALIGNMENT) sgx_key_request_t tmp_key_request;
    OE_ALIGNED(SGX_KEY_ALIGNMENT) sgx_key_t tmp_sgx_key;

    // Copy input parameter into local aligned buffers.
    oe_memcpy(&tmp_key_request, sgx_key_request, sizeof(sgx_key_request_t));

    // Execute EGETKEY instruction.
    egetkey_result = oe_egetkey(&tmp_key_request, &tmp_sgx_key);

    // Convert the EGETKEY result to oe_result_t.
    switch (egetkey_result)
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
        oe_memcpy(sgx_key, &tmp_sgx_key, sizeof(sgx_key_t));
        oe_memset(&tmp_sgx_key, 0, sizeof(sgx_key_t));
    }

    return ret;
}

oe_result_t oe_get_key(
    const sgx_key_request_t* sgx_key_request,
    sgx_key_t* sgx_key)
{
    // Check the input parameters.
    // Key request and key must be inside enclave.
    if ((sgx_key_request == NULL) ||
        !oe_is_within_enclave(sgx_key_request, sizeof(sgx_key_request_t)))
    {
        return OE_INVALID_PARAMETER;
    }

    if ((sgx_key == NULL) || !oe_is_within_enclave(sgx_key, sizeof(sgx_key_t)))
    {
        return OE_INVALID_PARAMETER;
    }

    // Reserved fields inside key request must be all zero.
    if (sgx_key_request->reserved1 != 0)
    {
        return OE_INVALID_PARAMETER;
    }

    for (size_t i = 0; i < OE_COUNTOF(sgx_key_request->reserved2); i++)
    {
        if (sgx_key_request->reserved2[i] != 0)
        {
            return OE_INVALID_PARAMETER;
        }
    }

    // Key name must be valid.
    if ((sgx_key_request->key_name < SGX_KEYSELECT_EINITTOKEN) ||
        (sgx_key_request->key_name > SGX_KEYSELECT_SEAL))
    {
        return OE_INVALID_PARAMETER;
    }

    // Reserved fields of key policy must be all zero.
    if (sgx_key_request->key_policy & ~(SGX_KEYPOLICY_ALL))
    {
        return OE_INVALID_PARAMETER;
    }

    return _get_key_imp(sgx_key_request, sgx_key);
}

oe_result_t oe_get_seal_key(
    const uint8_t* key_info,
    uint32_t key_info_size,
    uint8_t* key_buffer,
    uint32_t* key_buffer_size)
{
    oe_result_t ret;

    // Check parameters.
    if ((key_info == NULL) || (key_info_size != sizeof(sgx_key_request_t)))
    {
        return OE_INVALID_PARAMETER;
    }

    if ((key_buffer == NULL) || (key_buffer_size == NULL))
    {
        return OE_INVALID_PARAMETER;
    }

    if (*key_buffer_size < sizeof(sgx_key_t))
    {
        *key_buffer_size = sizeof(sgx_key_t);
        return OE_BUFFER_TOO_SMALL;
    }

    // Get the key based on input key info.
    ret = oe_get_key((sgx_key_request_t*)key_info, (sgx_key_t*)key_buffer);
    if (ret == OE_OK)
    {
        *key_buffer_size = sizeof(sgx_key_t);
    }

    return ret;
}

/*
 * Get default key request attributes.
 * The ISV SVN and CPU SVN are set to value of current enclave.
 * Attribute masks are set to OE default values.
 *
 * Return OE_OK and set attributes of sgx_key_request if success.
 * Otherwise return error and sgx_key_request is not changed.
 */
static oe_result_t _get_default_key_request_attributes(
    sgx_key_request_t* sgx_key_request)
{
    sgx_report_t sgx_report = {0};
    uint32_t sgx_report_size = sizeof(sgx_report_t);
    oe_result_t ret;

    // Get a local report of current enclave.
    ret = oe_get_report(
        0, NULL, 0, NULL, 0, (uint8_t*)&sgx_report, &sgx_report_size);

    if (ret != OE_OK)
    {
        return ret;
    }

    // Set key request attributes(isv svn, cpu svn, and attribute masks)
    sgx_key_request->isv_svn = sgx_report.body.isvsvn;
    oe_memcpy(
        &sgx_key_request->cpu_svn,
        sgx_report.body.cpusvn,
        OE_FIELD_SIZE(sgx_key_request_t, cpu_svn));
    sgx_key_request->attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgx_key_request->attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
    sgx_key_request->misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;
    return OE_OK;
}

oe_result_t oe_get_seal_key_by_policy(
    oe_seal_id_policy_t seal_policy,
    uint8_t* key_buffer,
    uint32_t* key_buffer_size,
    uint8_t* key_info,
    uint32_t* key_info_size)
{
    oe_result_t ret;
    sgx_key_request_t sgx_key_request = {0};

    // Check parameters.
    if (key_buffer == NULL || key_buffer_size == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    // Key buffer size must be big enough.
    if (*key_buffer_size < sizeof(sgx_key_t))
    {
        *key_buffer_size = sizeof(sgx_key_t);
        return OE_BUFFER_TOO_SMALL;
    }

    // Key info size must be big enough if request key info.
    if ((key_info != NULL) && (*key_info_size < sizeof(sgx_key_request_t)))
    {
        *key_info_size = sizeof(sgx_key_request_t);
        return OE_BUFFER_TOO_SMALL;
    }

    // Get default key request attributes.
    ret = _get_default_key_request_attributes(&sgx_key_request);
    if (ret != OE_OK)
    {
        return OE_UNEXPECTED;
    }

    // Set key name and key policy.
    sgx_key_request.key_name = SGX_KEYSELECT_SEAL;
    switch (seal_policy)
    {
        case OE_SEAL_ID_UNIQUE:
            sgx_key_request.key_policy = SGX_KEYPOLICY_MRENCLAVE;
            break;

        case OE_SEAL_ID_PRODUCT:
            sgx_key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;
            break;

        default:
            return OE_INVALID_PARAMETER;
    }

    // Get the seal key.
    ret = oe_get_key(&sgx_key_request, (sgx_key_t*)key_buffer);
    if (ret == OE_OK)
    {
        *key_buffer_size = sizeof(sgx_key_t);

        if (key_info != NULL)
        {
            oe_memcpy(key_info, &sgx_key_request, sizeof(sgx_key_request_t));
            *key_info_size = sizeof(sgx_key_request_t);
        }
    }
    else
    {
        // oe_get_key should not fail unless we set the key request wrong.
        ret = OE_UNEXPECTED;
    }

    return ret;
}
