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
    SGX_KeyRequest sgxKeyRequest = {0};
    SGX_Key sgxKey = {0};
    sgxKeyRequest.attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgxKeyRequest.attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
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
    SGX_KeyRequest sgxKeyRequest = {0};
    SGX_Key sgxKey = {0};
    sgxKeyRequest.attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgxKeyRequest.attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
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
        uint8_t keyBuffer[sizeof(SGX_Key)] = {0};
        uint32_t keyBufferSize = 0;
        OE_Result ret;

        // Get the seal key should fail if the keyBuffer is NULL.
        ret = OE_GetSealKeyByPolicy(
            (OE_SealIDPolicy)sealPolicy, NULL, NULL, NULL, NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }

        // Get the seal key should fail if the buffer is too small.
        ret = OE_GetSealKeyByPolicy(
            (OE_SealIDPolicy)sealPolicy, keyBuffer, &keyBufferSize, NULL, NULL);
        if (ret != OE_BUFFER_TOO_SMALL)
        {
            return false;
        }

        // The correct buffer size should be returned.
        OE_TEST(keyBufferSize == sizeof(SGX_Key));

        // Get the seal key by policy and without output the key info.
        ret = OE_GetSealKeyByPolicy(
            (OE_SealIDPolicy)sealPolicy, keyBuffer, &keyBufferSize, NULL, NULL);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(keyBufferSize == sizeof(SGX_Key));

        uint8_t secondKeyBuffer[sizeof(SGX_Key)] = {0};
        uint32_t secondKeyBufferSize = sizeof(secondKeyBuffer);
        uint8_t keyInfo[sizeof(SGX_KeyRequest)] = {0};
        uint32_t keyInfoSize = sizeof(keyInfo);

        // Get the seal key by policy and output the key info.
        ret = OE_GetSealKeyByPolicy(
            (OE_SealIDPolicy)sealPolicy,
            secondKeyBuffer,
            &secondKeyBufferSize,
            keyInfo,
            &keyInfoSize);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(secondKeyBufferSize == sizeof(SGX_Key));
        OE_TEST(keyInfoSize == sizeof(SGX_KeyRequest));

        uint8_t thirdKeyBuffer[sizeof(SGX_Key)] = {0};
        uint32_t thirdKeyBufferSize = sizeof(thirdKeyBuffer);

        // Get the seal key using saved key info.
        ret = OE_GetSealKey(
            keyInfo, keyInfoSize, thirdKeyBuffer, &thirdKeyBufferSize);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(thirdKeyBufferSize == sizeof(SGX_Key));

        // The seal keys should match.
        if ((OE_Memcmp(keyBuffer, secondKeyBuffer, sizeof(SGX_Key)) != 0) ||
            (OE_Memcmp(keyBuffer, thirdKeyBuffer, sizeof(SGX_Key)) != 0))
        {
            return false;
        }

        // Modify the isv_svn of key request to invalid and verify the function
        // can't get seal key.
        SGX_KeyRequest* keyRequest = (SGX_KeyRequest*)keyInfo;
        uint16_t curIsvSvn = keyRequest->isv_svn;
        keyRequest->isv_svn = 0XFFFF;
        ret = OE_GetSealKey(
            keyInfo, keyInfoSize, thirdKeyBuffer, &thirdKeyBufferSize);
        if (ret != OE_INVALID_ISVSVN)
        {
            return false;
        }

        // Modify the cpu_svn of key request to invalid and verify the function
        // can't get seal key.
        keyRequest->isv_svn = curIsvSvn;
        OE_Memset(
            keyRequest->cpu_svn, 0XFF, OE_FIELD_SIZE(SGX_KeyRequest, cpu_svn));
        ret = OE_GetSealKey(
            keyInfo, keyInfoSize, thirdKeyBuffer, &thirdKeyBufferSize);
        if (ret != OE_INVALID_CPUSVN)
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
