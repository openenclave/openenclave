
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/keys.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include "sealKey_t.h"

// A regular enclave should not have access to SGX_KEYSELECT_EINITTOKEN,
// SGX_KEYSELECT_PROVISION, and SGX_KEYSELECT_PROVISION_SEAL keys.
bool TestOEGetPrivilegeKeys()
{
    oe_result_t result;
    sgx_key_request_t sgx_key_request = {0};
    sgx_key_t sgx_key = {0};
    sgx_key_request.attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgx_key_request.attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
    sgx_key_request.misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;

    for (uint16_t key_name = SGX_KEYSELECT_EINITTOKEN;
         key_name <= SGX_KEYSELECT_PROVISION_SEAL;
         key_name++)
    {
        sgx_key_request.key_name = key_name;
        for (uint16_t key_policy = SGX_KEYPOLICY_MRENCLAVE;
             key_policy <= SGX_KEYPOLICY_MRSIGNER;
             key_policy++)
        {
            sgx_key_request.key_policy = key_policy;
            result = oe_get_key(&sgx_key_request, &sgx_key);
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
    sgx_key_request_t sgx_key_request = {0};
    sgx_key_t sgx_key = {0};
    sgx_key_request.attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    sgx_key_request.attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
    sgx_key_request.misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;

    for (uint16_t key_name = SGX_KEYSELECT_REPORT;
         key_name <= SGX_KEYSELECT_SEAL;
         key_name++)
    {
        sgx_key_request.key_name = key_name;
        for (uint16_t key_policy = SGX_KEYPOLICY_MRENCLAVE;
             key_policy <= SGX_KEYPOLICY_MRSIGNER;
             key_policy++)
        {
            sgx_key_request.key_policy = key_policy;
            result = oe_get_key(&sgx_key_request, &sgx_key);
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
    for (uint32_t seal_policy = OE_SEAL_POLICY_UNIQUE;
         seal_policy <= OE_SEAL_POLICY_PRODUCT;
         seal_policy++)
    {
        uint8_t key_buffer[sizeof(sgx_key_t)] = {0};
        size_t key_buffer_size = 0;
        oe_result_t ret;

        // Get the seal key should fail if the key_buffer is NULL.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)seal_policy, NULL, NULL, NULL, NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }

        // Get the seal key should fail if the buffer is too small.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)seal_policy,
            key_buffer,
            &key_buffer_size,
            NULL,
            NULL);
        if (ret != OE_BUFFER_TOO_SMALL)
        {
            return false;
        }

        // The correct buffer size should be returned.
        OE_TEST(key_buffer_size == sizeof(sgx_key_t));

        // Get the seal key by policy and without output the key info.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)seal_policy,
            key_buffer,
            &key_buffer_size,
            NULL,
            NULL);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(key_buffer_size == sizeof(sgx_key_t));

        uint8_t second_key_buffer[sizeof(sgx_key_t)] = {0};
        size_t second_key_buffer_size = sizeof(second_key_buffer);
        uint8_t key_info[sizeof(sgx_key_request_t)] = {0};
        size_t key_info_size = sizeof(key_info);

        // Get the seal key by policy and output the key info.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)seal_policy,
            second_key_buffer,
            &second_key_buffer_size,
            key_info,
            &key_info_size);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(second_key_buffer_size == sizeof(sgx_key_t));
        OE_TEST(key_info_size == sizeof(sgx_key_request_t));

        uint8_t third_key_buffer[sizeof(sgx_key_t)] = {0};
        size_t third_key_buffer_size = sizeof(third_key_buffer);

        // Get the seal key using saved key info.
        ret = oe_get_seal_key(
            key_info, key_info_size, third_key_buffer, &third_key_buffer_size);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(third_key_buffer_size == sizeof(sgx_key_t));

        // The seal keys should match.
        if ((oe_memcmp(key_buffer, second_key_buffer, sizeof(sgx_key_t)) !=
             0) ||
            (oe_memcmp(key_buffer, third_key_buffer, sizeof(sgx_key_t)) != 0))
        {
            return false;
        }

        // Modify the isv_svn of key request to invalid and verify the function
        // can't get seal key.
        sgx_key_request_t* key_request = (sgx_key_request_t*)key_info;
        uint16_t cur_isv_svn = key_request->isv_svn;
        key_request->isv_svn = 0XFFFF;
        ret = oe_get_seal_key(
            key_info, key_info_size, third_key_buffer, &third_key_buffer_size);
        if (ret != OE_INVALID_ISVSVN)
        {
            return false;
        }

        // Modify the cpu_svn of key request to invalid and verify the function
        // can't get seal key.
        key_request->isv_svn = cur_isv_svn;
        oe_memset(
            key_request->cpu_svn,
            0XFF,
            OE_FIELD_SIZE(sgx_key_request_t, cpu_svn));
        ret = oe_get_seal_key(
            key_info, key_info_size, third_key_buffer, &third_key_buffer_size);
        if (ret != OE_INVALID_CPUSVN)
        {
            return false;
        }
    }

    return true;
}

int test_seal_key(int in)
{
    if (TestOEGetPrivilegeKeys() && TestOEGetRegularKeys() &&
        TestOEGetSealKey())
    {
        return 0;
    }

    return in;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    5);   /* TCSCount */
