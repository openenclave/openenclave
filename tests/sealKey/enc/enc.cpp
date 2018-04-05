// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/keys.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/tests.h>
#include <openenclave/enclave.h>
#include "../args.h"

// A regular enclave should not have access to SGX_KEYSELECT_EINITTOKEN,
// SGX_KEYSELECT_PROVISION, and SGX_KEYSELECT_PROVISION_SEAL keys.
bool TestOEGetPrivilegeKeys()
{
    OE_Result result;
    Sgx_KeyRequest sgxKeyRequest = {0};
    Sgx_Key sgxKey = {0};
    sgxKeyRequest.flags_attribute_mask = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgxKeyRequest.xfrm_attribute_mask = OE_SEALKEY_DEFAULT_XFRMMASK;
    sgxKeyRequest.misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;

    for (uint16_t keyName = SGX_KEYSELECT_EINITTOKEN;
         keyName <= SGX_KEYSELECT_PROVISION_SEAL;
         keyName++)
    {
        sgxKeyRequest.key_name = keyName;
        for (uint16_t keyPolicy = SGX_KEYPOLICY_MRENCLAVE;
             keyPolicy <= SGX_KEYPOLICY_MRSIGNER;
             keyPolicy++)
        {
            sgxKeyRequest.key_policy = keyPolicy;
            result = OE_GetKey(&sgxKeyRequest, &sgxKey);
            if (result == OE_OK)
            {
                return false;
            }
        }
    }

    return true;
}

// An enclave should be able to access SGX_KEYSELECT_REPORT and
// SGX_KEYSELECT_SEAL keys.
bool TestOEGetRegularKeys()
{
    OE_Result result;
    Sgx_KeyRequest sgxKeyRequest = {0};
    Sgx_Key sgxKey = {0};
    sgxKeyRequest.flags_attribute_mask = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgxKeyRequest.xfrm_attribute_mask = OE_SEALKEY_DEFAULT_XFRMMASK;
    sgxKeyRequest.misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;

    for (uint16_t keyName = SGX_KEYSELECT_REPORT; keyName <= SGX_KEYSELECT_SEAL;
         keyName++)
    {
        sgxKeyRequest.key_name = keyName;
        for (uint16_t keyPolicy = SGX_KEYPOLICY_MRENCLAVE;
             keyPolicy <= SGX_KEYPOLICY_MRSIGNER;
             keyPolicy++)
        {
            sgxKeyRequest.key_policy = keyPolicy;
            result = OE_GetKey(&sgxKeyRequest, &sgxKey);
            if (result != OE_OK)
            {
                return false;
            }
        }
    }

    return true;
}

// Test the high level API.
// The high level seal key API should be able to get sealing keys.
bool TestOEGetSealKey()
{
    for (uint32_t sealPolicy = OE_SEAL_ID_UNIQUE;
         sealPolicy <= OE_SEAL_ID_PRODUCT;
         sealPolicy++)
    {
        uint8_t keyBuffer[sizeof(Sgx_Key)] = {0};
        uint32_t keyBufferSize = 0;
        OE_Result ret;

        // Get the seal key should fail if the buffer is too small.
        ret = OE_GetSealKeyByPolicy(
            (OE_SEAL_ID_POLICY)sealPolicy,
            keyBuffer,
            &keyBufferSize,
            NULL,
            NULL);
        if (ret != OE_BUFFER_TOO_SMALL)
        {
            return false;
        }

        // The correct buffer size should be returned.
        OE_TEST(keyBufferSize == sizeof(Sgx_Key));

        // Get the seal key by policy and without output the key info.
        ret = OE_GetSealKeyByPolicy(
            (OE_SEAL_ID_POLICY)sealPolicy,
            keyBuffer,
            &keyBufferSize,
            NULL,
            NULL);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(keyBufferSize == sizeof(Sgx_Key));

        uint8_t secondKeyBuffer[sizeof(Sgx_Key)] = {0};
        uint32_t secondKeyBufferSize = sizeof(secondKeyBuffer);
        uint8_t keyInfo[sizeof(Sgx_KeyRequest)] = {0};
        uint32_t keyInfoSize = sizeof(keyInfo);

        // Get the seal key by policy and output the key info.
        ret = OE_GetSealKeyByPolicy(
            (OE_SEAL_ID_POLICY)sealPolicy,
            secondKeyBuffer,
            &secondKeyBufferSize,
            keyInfo,
            &keyInfoSize);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(secondKeyBufferSize == sizeof(Sgx_Key));
        OE_TEST(keyInfoSize == sizeof(Sgx_KeyRequest));

        uint8_t thirdKeyBuffer[sizeof(Sgx_Key)] = {0};
        uint32_t thirdKeyBufferSize = sizeof(thirdKeyBuffer);

        // Get the seal key using saved key info.
        ret = OE_GetSealKey(
            keyInfo, keyInfoSize, thirdKeyBuffer, &thirdKeyBufferSize);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(thirdKeyBufferSize == sizeof(Sgx_Key));

        // The seal keys should match.
        if ((OE_Memcmp(keyBuffer, secondKeyBuffer, sizeof(Sgx_Key)) != 0) ||
            (OE_Memcmp(keyBuffer, thirdKeyBuffer, sizeof(Sgx_Key)) != 0))
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

    if (TestOEGetPrivilegeKeys() && TestOEGetRegularKeys() &&
        TestOEGetSealKey())
    {
        args->ret = 0;
    }

    return;
}