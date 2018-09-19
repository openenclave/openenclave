// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/keys.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

// A regular enclave should not have access to SGX_KEYSELECT_EINITTOKEN,
// SGX_KEYSELECT_PROVISION, and SGX_KEYSELECT_PROVISION_SEAL keys.
bool TestOEGetPrivilegeKeys()
{
    oe_result_t result;
    sgx_key_request_t sgxKeyRequest = {0};
    sgx_key_t sgxKey = {0};
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
            result = oe_get_key(&sgxKeyRequest, &sgxKey);
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
    oe_result_t result;
    sgx_key_request_t sgxKeyRequest = {0};
    sgx_key_t sgxKey = {0};
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
            result = oe_get_key(&sgxKeyRequest, &sgxKey);
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
    for (uint32_t sealPolicy = OE_SEAL_POLICY_UNIQUE;
         sealPolicy <= OE_SEAL_POLICY_PRODUCT;
         sealPolicy++)
    {
        uint8_t keyBuffer[sizeof(sgx_key_t)] = {0};
        size_t keyBufferSize = 0;
        oe_result_t ret;

        // Get the seal key should fail if the keyBuffer is NULL.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)sealPolicy, NULL, NULL, NULL, NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }

        // Get the seal key should fail if the buffer is too small.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)sealPolicy,
            keyBuffer,
            &keyBufferSize,
            NULL,
            NULL);
        if (ret != OE_BUFFER_TOO_SMALL)
        {
            return false;
        }

        // The correct buffer size should be returned.
        OE_TEST(keyBufferSize == sizeof(sgx_key_t));

        // Get the seal key by policy and without output the key info.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)sealPolicy,
            keyBuffer,
            &keyBufferSize,
            NULL,
            NULL);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(keyBufferSize == sizeof(sgx_key_t));

        uint8_t secondKeyBuffer[sizeof(sgx_key_t)] = {0};
        size_t secondKeyBufferSize = sizeof(secondKeyBuffer);
        uint8_t keyInfo[sizeof(sgx_key_request_t)] = {0};
        size_t keyInfoSize = sizeof(keyInfo);

        // Get the seal key by policy and output the key info.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)sealPolicy,
            secondKeyBuffer,
            &secondKeyBufferSize,
            keyInfo,
            &keyInfoSize);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(secondKeyBufferSize == sizeof(sgx_key_t));
        OE_TEST(keyInfoSize == sizeof(sgx_key_request_t));

        uint8_t thirdKeyBuffer[sizeof(sgx_key_t)] = {0};
        size_t thirdKeyBufferSize = sizeof(thirdKeyBuffer);

        // Get the seal key using saved key info.
        ret = oe_get_seal_key(
            keyInfo, keyInfoSize, thirdKeyBuffer, &thirdKeyBufferSize);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(thirdKeyBufferSize == sizeof(sgx_key_t));

        // The seal keys should match.
        if ((oe_memcmp(keyBuffer, secondKeyBuffer, sizeof(sgx_key_t)) != 0) ||
            (oe_memcmp(keyBuffer, thirdKeyBuffer, sizeof(sgx_key_t)) != 0))
        {
            return false;
        }

        // Modify the isv_svn of key request to invalid and verify the function
        // can't get seal key.
        sgx_key_request_t* keyRequest = (sgx_key_request_t*)keyInfo;
        uint16_t curIsvSvn = keyRequest->isv_svn;
        keyRequest->isv_svn = 0XFFFF;
        ret = oe_get_seal_key(
            keyInfo, keyInfoSize, thirdKeyBuffer, &thirdKeyBufferSize);
        if (ret != OE_INVALID_ISVSVN)
        {
            return false;
        }

        // Modify the cpu_svn of key request to invalid and verify the function
        // can't get seal key.
        keyRequest->isv_svn = curIsvSvn;
        oe_memset(
            keyRequest->cpu_svn,
            0XFF,
            OE_FIELD_SIZE(sgx_key_request_t, cpu_svn));
        ret = oe_get_seal_key(
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

    if (!oe_is_outside_enclave(args, sizeof(SealKeyArgs)))
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

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    5);   /* TCSCount */
