// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/atexit.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/fault.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/jump.h>
#include <openenclave/bits/reloc.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/enclave.h>
#include "asmdefs.h"
#include "cpuid.h"
#include "init.h"
#include "report.h"
#include "td.h"


// Todo: move them to C:\Users\mattkou\Source\Repos\openenclave\include\openenclave\bits\sgxtypes.h
// Refer to 38.17 KEY REQUEST (KEYREQUEST) in Intel SDM.
// Field size.
#define SGX_KEYID_SIZE    32
#define SGX_CPUSVN_SIZE   16

// Key name.
#define SGX_KEYSELECT_EINITTOKEN       0x0000U
#define SGX_KEYSELECT_PROVISION        0x0001U
#define SGX_KEYSELECT_PROVISION_SEAL   0x0002U
#define SGX_KEYSELECT_REPORT           0x0003U
#define SGX_KEYSELECT_SEAL             0x0004U

// Key policy.
#define SGX_KEYPOLICY_MRENCLAVE        0x0001U
#define SGX_KEYPOLICY_MRSIGNER         0x0002U
#define SGX_KEYPOLICY_ALL   (SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER)

OE_PACK_BEGIN
typedef struct _Sgx_KeyRequest
{
    uint16_t key_name;
    uint16_t key_policy;
    uint16_t isv_svn;
    uint16_t reserved1;
    uint8_t  cpu_svn[SGX_CPUSVN_SIZE];
    uint64_t flags_attribute_mask;
    uint64_t xfrm_attribute_mask;
    uint8_t  key_id[SGX_KEYID_SIZE];
    uint32_t misc_attribute_mask;
    uint8_t  reserved2[436];
} Sgx_KeyRequest;
OE_PACK_END

OE_STATIC_ASSERT(sizeof(Sgx_KeyRequest) == 512);

// Refer to EGETKEY leaf instruction in Intel SDM.
// EGETKEY instruction return values. 
#define SGX_SUCCESS             0
#define SGX_INVALID_ATTRIBUTE   (1 << (1))
#define SGX_INVALID_CPUSVN      (1 << (5))
#define SGX_INVALID_ISVSVN      (1 << (6))
#define SGX_INVALID_KEYNAME     (1 << (8))

// Alignment requirement.
#define SGX_KEY_REQUEST_ALIGNMENT 512
#define SGX_KEY_ALIGNMENT 16

// The 128-bit SGX secret key.
typedef uint8_t Sgx_Key[16];

uint64_t _OE_EGetKey(const Sgx_KeyRequest* sgxKeyRequest, Sgx_Key* sgxKey);

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
* Get a 128-bit secret SGX key.
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

int TestGetKey()
{
    OE_Result result;
    Sgx_KeyRequest sgxKeyRequest = { 0 };
    Sgx_Key sgxKey = { 0 };

    for (uint16_t i = SGX_KEYSELECT_EINITTOKEN; i <= SGX_KEYSELECT_SEAL; i++)
    {
        sgxKeyRequest.key_name = i;
        sgxKeyRequest.key_policy = SGX_KEYPOLICY_MRENCLAVE;
        sgxKeyRequest.flags_attribute_mask = ~((uint64_t)0x0);
        sgxKeyRequest.xfrm_attribute_mask = ~((uint64_t)0x0);

        result = OE_GetKey(&sgxKeyRequest, &sgxKey);

        sgxKeyRequest.key_policy = SGX_KEYPOLICY_MRSIGNER;
        result = OE_GetKey(&sgxKeyRequest, &sgxKey);
    }

    return result;
}