// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/keys.h>
#include <openenclave/enclave.h>
#include "../args.h"

// Test the low level API.
bool TestOEGetKey()
{
    OE_Result result;

    {
        // A regular enclave should not have access to SGX_KEYSELECT_EINITTOKEN,
        // SGX_KEYSELECT_PROVISION, and SGX_KEYSELECT_PROVISION_SEAL keys.
        Sgx_KeyRequest sgxKeyRequest = { 0 };
        Sgx_Key sgxKey = { 0 };
        sgxKeyRequest.flags_attribute_mask = OE_SEALKEY_DEFAULT_FLAGSMASK;
        sgxKeyRequest.xfrm_attribute_mask = OE_SEALKEY_DEFAULT_XFRMMASK;
        sgxKeyRequest.misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;

        for (uint16_t keyName = SGX_KEYSELECT_EINITTOKEN; 
            keyName <= SGX_KEYSELECT_PROVISION_SEAL; keyName++)
        {
            sgxKeyRequest.key_name = keyName;
            for (uint16_t keyPolicy = SGX_KEYPOLICY_MRENCLAVE;
                keyPolicy <= SGX_KEYPOLICY_MRSIGNER; keyPolicy++)
            {
                sgxKeyRequest.key_policy = keyPolicy;
                result = OE_GetKey(&sgxKeyRequest, &sgxKey);
                if (result == OE_OK)
                {
                    return false;
                }
            }
        }
    }

    {
        // An enclave should be able to access SGX_KEYSELECT_REPORT and
        // SGX_KEYSELECT_SEAL keys.
        Sgx_KeyRequest sgxKeyRequest = { 0 };
        Sgx_Key sgxKey = { 0 };
        sgxKeyRequest.flags_attribute_mask = OE_SEALKEY_DEFAULT_FLAGSMASK;
        sgxKeyRequest.xfrm_attribute_mask = OE_SEALKEY_DEFAULT_XFRMMASK;
        sgxKeyRequest.misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;

        for (uint16_t keyName = SGX_KEYSELECT_REPORT; 
            keyName <= SGX_KEYSELECT_SEAL; keyName++)
        {
            sgxKeyRequest.key_name = keyName;
            for (uint16_t keyPolicy = SGX_KEYPOLICY_MRENCLAVE;
                keyPolicy <= SGX_KEYPOLICY_MRSIGNER; keyPolicy++)
            {
                sgxKeyRequest.key_policy = keyPolicy;
                result = OE_GetKey(&sgxKeyRequest, &sgxKey);
                if (result != OE_OK)
                {
                    return false;
                }
            }
        }
    }

    return true;
}

// Test the high level API.
bool TestOEGetSealKey()
{
    // The high level seal key API should be able to get sealing keys.
    for (uint32_t sealPolicy = OE_SEAL_ID_UNIQUE; 
        sealPolicy <= OE_SEAL_ID_PRODUCT; sealPolicy++)
    {
        uint8_t keyBuffer[sizeof(Sgx_Key)] = { 0 };
        uint32_t keyBufferSize = sizeof(keyBuffer);
        uint8_t keyInfo[sizeof(Sgx_KeyRequest)] = { 0 };
        uint32_t keyInfoSize = sizeof(keyInfo);
        OE_Result ret;

        // Get the seal key by policy and output the key info.
        ret = OE_GetSealKeyByPolicy(
            (OE_SEAL_ID_POLICY)sealPolicy,
            keyBuffer, 
            &keyBufferSize,
            keyInfo, 
            &keyInfoSize);
        if (ret != OE_OK)
        {
            return false;
        }

        uint8_t keyBufferTmp[sizeof(Sgx_Key)] = { 0 };
        uint32_t keyBufferTmpSize = sizeof(keyBufferTmp);

        // Get the seal key by saved key info.
        ret = OE_GetSealKey(
            keyInfo, 
            keyInfoSize, 
            keyBufferTmp, 
            &keyBufferTmpSize);
        if (ret != OE_OK)
        {
            return false;
        }

        // The seal key should match.
        if (OE_Memcmp(keyBuffer, keyBufferTmp, sizeof(Sgx_Key)) != 0)
        {
            return false;
        }
    }

    return true;
}


OE_ECALL void TestSealKey(void* args_)
{
    SealKeyArgs* args = (SealKeyArgs*)args_;

    if (!OE_IsOutsideEnclave(args, sizeof(SealKeyArgs)))
    {
        return;
    }

    if (TestOEGetKey() && TestOEGetSealKey())
    {
        args->ret = 0;
    }

    return;
}