
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgxkeys.h>
#include <openenclave/internal/tests.h>
#include <stdlib.h>
#include <string.h>
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
        uint8_t* key_buffer_ptr = NULL;
        size_t key_buffer_ptr_size = 0;
        oe_result_t ret;

        // Get the seal key should fail if the key_buffer is NULL.
        ret = oe_get_seal_key_by_policy_v2(
            (oe_seal_policy_t)seal_policy, NULL, NULL, NULL, NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)seal_policy, NULL, NULL, NULL, NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }
        ret = oe_get_seal_key_by_policy_v2(
            (oe_seal_policy_t)seal_policy, &key_buffer_ptr, NULL, NULL, NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)seal_policy, &key_buffer_ptr, NULL, NULL, NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }
        ret = oe_get_seal_key_by_policy_v2(
            (oe_seal_policy_t)seal_policy,
            NULL,
            &key_buffer_ptr_size,
            NULL,
            NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)seal_policy,
            NULL,
            &key_buffer_ptr_size,
            NULL,
            NULL);
        if (ret != OE_INVALID_PARAMETER)
        {
            return false;
        }

        // Get the seal key by policy and without output the key info.
        ret = oe_get_seal_key_by_policy_v2(
            (oe_seal_policy_t)seal_policy,
            &key_buffer_ptr,
            &key_buffer_ptr_size,
            NULL,
            NULL);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(key_buffer_ptr_size == sizeof(sgx_key_t));

        uint8_t* second_key_buffer_ptr = NULL;
        size_t second_key_buffer_ptr_size = 0;
        uint8_t* key_info_ptr = NULL;
        size_t key_info_ptr_size = 0;

        // Get the seal key by policy and output the key info.
        ret = oe_get_seal_key_by_policy_v2(
            (oe_seal_policy_t)seal_policy,
            &second_key_buffer_ptr,
            &second_key_buffer_ptr_size,
            &key_info_ptr,
            &key_info_ptr_size);
        if (ret != OE_OK)
        {
            return false;
        }

        oe_free_seal_key(second_key_buffer_ptr, key_info_ptr);

        OE_TEST(second_key_buffer_ptr_size == sizeof(sgx_key_t));
        OE_TEST(key_info_ptr_size == sizeof(sgx_key_request_t));

        second_key_buffer_ptr = NULL;
        key_info_ptr = NULL;
        key_info_ptr_size = NULL;

        // Get the seal key by policy and output the key info.
        ret = oe_get_seal_key_by_policy(
            (oe_seal_policy_t)seal_policy,
            &second_key_buffer_ptr,
            &second_key_buffer_ptr_size,
            &key_info_ptr,
            &key_info_ptr_size);
        if (ret != OE_OK)
        {
            return false;
        }

        oe_free_seal_key(second_key_buffer_ptr, NULL);

        OE_TEST(second_key_buffer_ptr_size == sizeof(sgx_key_t));
        OE_TEST(key_info_ptr_size == sizeof(sgx_key_request_t));

        uint8_t* third_key_ptr;
        size_t third_key_ptr_size;

        // Get the seal key using saved key info.
        ret = oe_get_seal_key_v2(
            key_info_ptr,
            key_info_ptr_size,
            &third_key_ptr,
            &third_key_ptr_size);
        if (ret != OE_OK)
        {
            return false;
        }

        OE_TEST(third_key_ptr_size == sizeof(sgx_key_t));

        // The seal keys should match.
        if ((memcmp(key_buffer_ptr, third_key_ptr, sizeof(sgx_key_t)) != 0))
        {
            oe_free_seal_key(third_key_ptr, NULL);
            return false;
        }

        oe_free_seal_key(third_key_ptr, NULL);

        // Modify the isv_svn of key request to invalid and verify the function
        // can't get seal key.
        sgx_key_request_t* key_request = (sgx_key_request_t*)key_info_ptr;
        uint16_t cur_isv_svn = key_request->isv_svn;
        key_request->isv_svn = 0XFFFF;
        ret = oe_get_seal_key_v2(
            key_info_ptr,
            key_info_ptr_size,
            &third_key_ptr,
            &third_key_ptr_size);
        if (ret != OE_INVALID_ISVSVN)
        {
            if (ret == OE_OK)
            {
                oe_free_seal_key(third_key_ptr, NULL);
            }
            return false;
        }

        // Modify the cpu_svn of key request to invalid and verify the function
        // can't get seal key.
        key_request->isv_svn = cur_isv_svn;
        memset(
            key_request->cpu_svn,
            0XFF,
            OE_FIELD_SIZE(sgx_key_request_t, cpu_svn));
        ret = oe_get_seal_key_v2(
            key_info_ptr,
            key_info_ptr_size,
            &third_key_ptr,
            &third_key_ptr_size);
        if (ret != OE_INVALID_CPUSVN)
        {
            if (ret == OE_OK)
            {
                oe_free_seal_key(third_key_ptr, NULL);
            }
            return false;
        }

        oe_free_seal_key(key_buffer_ptr, NULL);
        oe_free_seal_key(NULL, key_info_ptr);
    }

    return true;
}

bool TestPubPrivKey(
    const uint8_t* pubkey,
    size_t pubkey_size,
    const uint8_t* privkey,
    size_t privkey_size)
{
    oe_ec_public_key_t oe_pubkey;
    oe_ec_private_key_t oe_privkey;
    oe_result_t result;
    uint8_t data[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };
    uint8_t* signature = NULL;
    size_t signature_size = 0;

    result = oe_ec_public_key_read_pem(&oe_pubkey, pubkey, pubkey_size);
    if (result != OE_OK)
        return false;

    result = oe_ec_private_key_read_pem(&oe_privkey, privkey, privkey_size);
    if (result != OE_OK)
        return false;

    result = oe_ec_private_key_sign(
        &oe_privkey,
        OE_HASH_TYPE_SHA256,
        data,
        sizeof(data),
        signature,
        &signature_size);

    if (result != OE_BUFFER_TOO_SMALL)
        return false;

    signature = (uint8_t*)malloc(signature_size);
    if (signature == NULL)
        return false;

    result = oe_ec_private_key_sign(
        &oe_privkey,
        OE_HASH_TYPE_SHA256,
        data,
        sizeof(data),
        signature,
        &signature_size);

    if (result != OE_OK)
        return false;

    result = oe_ec_public_key_verify(
        &oe_pubkey,
        OE_HASH_TYPE_SHA256,
        data,
        sizeof(data),
        signature,
        signature_size);

    if (result != OE_OK)
        return false;

    free(signature);
    oe_ec_public_key_free(&oe_pubkey);
    oe_ec_private_key_free(&oe_privkey);
    return true;
}

bool TestAsymKeyCase(
    oe_seal_policy_t seal_policy,
    const oe_asymmetric_key_params_t* params)
{
    uint8_t* pubkey = NULL;
    size_t pubkey_size = 0;
    uint8_t* privkey = NULL;
    size_t privkey_size = 0;
    uint8_t* pubkey2 = NULL;
    size_t pubkey2_size = 0;
    uint8_t* privkey2 = NULL;
    size_t privkey2_size = 0;
    uint8_t* keyinfo = NULL;
    size_t keyinfo_size = 0;
    uint8_t* keyinfo2 = NULL;
    size_t keyinfo2_size = 0;
    sgx_key_request_t* key_request;
    oe_result_t ret;

    // Try out the policy one first, we should get the right public/private
    // pair
    ret = oe_get_public_key_by_policy(
        (oe_seal_policy_t)seal_policy,
        params,
        &pubkey,
        &pubkey_size,
        NULL,
        NULL);

    if (ret != OE_OK)
        return false;

    ret = oe_get_private_key_by_policy(
        (oe_seal_policy_t)seal_policy,
        params,
        &privkey,
        &privkey_size,
        NULL,
        NULL);

    if (ret != OE_OK)
        return false;

    if (!TestPubPrivKey(pubkey, pubkey_size, privkey, privkey_size))
        return false;

    // Now try with the key info structs.
    ret = oe_get_public_key_by_policy(
        (oe_seal_policy_t)seal_policy,
        params,
        &pubkey2,
        &pubkey2_size,
        &keyinfo,
        &keyinfo_size);

    if (ret != OE_OK)
        return false;

    ret = oe_get_private_key_by_policy(
        (oe_seal_policy_t)seal_policy,
        params,
        &privkey2,
        &privkey2_size,
        &keyinfo2,
        &keyinfo2_size);

    if (ret != OE_OK)
        return false;

    // The keys should have not changed.
    if (pubkey_size != pubkey2_size || privkey_size != privkey2_size)
        return false;

    if (memcmp(pubkey, pubkey2, pubkey_size) != 0 ||
        memcmp(privkey, privkey2, privkey_size) != 0)
    {
        return false;
    }

    // The key infos should be the same.
    if (keyinfo_size != keyinfo2_size ||
        memcmp(keyinfo, keyinfo2, keyinfo_size) != 0)
    {
        return false;
    }

    if (!TestPubPrivKey(pubkey2, pubkey2_size, privkey2, privkey2_size))
        return false;

    // Now try the API using the key info as input.
    oe_free_key(pubkey2, pubkey2_size, NULL, 0);
    oe_free_key(privkey2, privkey2_size, NULL, 0);
    ret = oe_get_public_key(
        params, keyinfo, keyinfo_size, &pubkey2, &pubkey2_size);

    if (ret != OE_OK)
        return false;

    ret = oe_get_private_key(
        params, keyinfo, keyinfo_size, &privkey2, &privkey2_size);

    if (ret != OE_OK)
        return false;

    // The keys should have not changed.
    if (pubkey_size != pubkey2_size || privkey_size != privkey2_size)
        return false;

    if (memcmp(pubkey, pubkey2, pubkey_size) != 0 ||
        memcmp(privkey, privkey2, privkey_size) != 0)
    {
        return false;
    }

    if (!TestPubPrivKey(pubkey2, pubkey2_size, privkey2, privkey2_size))
        return false;

    // Modify the isv_svn of key request to invalid and verify the function
    // can't get seal key.
    key_request = (sgx_key_request_t*)keyinfo;
    uint16_t cur_isv_svn = key_request->isv_svn;
    key_request->isv_svn = 0XFFFF;
    ret = oe_get_public_key(
        params, keyinfo, keyinfo_size, &pubkey2, &pubkey2_size);

    if (ret != OE_INVALID_ISVSVN)
        return false;

    ret = oe_get_private_key(
        params, keyinfo, keyinfo_size, &privkey2, &privkey2_size);

    if (ret != OE_INVALID_ISVSVN)
        return false;

    // Modify the cpu_svn of key request to invalid and verify the function
    // can't get seal key.
    key_request->isv_svn = cur_isv_svn;
    memset(
        key_request->cpu_svn, 0XFF, OE_FIELD_SIZE(sgx_key_request_t, cpu_svn));

    ret = oe_get_public_key(
        params, keyinfo, keyinfo_size, &pubkey2, &pubkey2_size);

    if (ret != OE_INVALID_CPUSVN)
        return false;

    ret = oe_get_private_key(
        params, keyinfo, keyinfo_size, &privkey2, &privkey2_size);

    if (ret != OE_INVALID_CPUSVN)
        return false;

    oe_free_key(pubkey, pubkey_size, NULL, 0);
    oe_free_key(privkey, privkey_size, keyinfo, keyinfo_size);
    oe_free_key(pubkey2, pubkey2_size, NULL, 0);
    oe_free_key(privkey2, privkey2_size, keyinfo2, keyinfo2_size);
    return true;
}

// Test high level APIs for getting asymmetric keys that are derived based off
// the seal key (oe_get_[public|private][_by_policy]).
bool TestAsymKey()
{
    for (uint32_t seal_policy = OE_SEAL_POLICY_UNIQUE;
         seal_policy <= OE_SEAL_POLICY_PRODUCT;
         seal_policy++)
    {
        oe_asymmetric_key_params_t params;
        char data[] = "Hello World!";
        size_t datalen = sizeof(data) - 1;

        // First, generate the key with a null user data.
        params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
        params.format = OE_ASYMMETRIC_KEY_PEM;
        params.user_data = NULL;
        params.user_data_size = 0;
        if (!TestAsymKeyCase((oe_seal_policy_t)seal_policy, &params))
            return false;

        // Second, generate the key with some user data.
        params.user_data = data;
        params.user_data_size = datalen;
        if (!TestAsymKeyCase((oe_seal_policy_t)seal_policy, &params))
            return false;

        // Lastly, try invalid params.
        params.type = _OE_ASYMMETRIC_KEY_TYPE_MAX;
        params.format = OE_ASYMMETRIC_KEY_PEM;
        if (TestAsymKeyCase((oe_seal_policy_t)seal_policy, &params))
            return false;

        params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
        params.format = _OE_ASYMMETRIC_KEY_FORMAT_MAX;
        if (TestAsymKeyCase((oe_seal_policy_t)seal_policy, &params))
            return false;
    }

    return true;
}

int test_seal_key(int in)
{
    if (TestOEGetPrivilegeKeys() && TestOEGetRegularKeys() &&
        TestOEGetSealKey() && TestAsymKey())
    {
        return 0;
    }

    return in;
}

int enc_get_public_key_by_policy(
    int policy,
    const char* data,
    uint8_t* keybuf,
    size_t keybuf_maxsize,
    size_t* keybuf_size,
    uint8_t* keyinfo,
    size_t keyinfo_maxsize,
    size_t* keyinfo_size)
{
    oe_asymmetric_key_params_t params;
    oe_result_t ret;
    uint8_t* pubkey = NULL;
    size_t pubkey_size = 0;
    uint8_t* pubkey_info = NULL;
    size_t pubkey_info_size = 0;

    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = (void*)data;
    params.user_data_size = data ? strlen(data) : 0;

    ret = oe_get_public_key_by_policy(
        (oe_seal_policy_t)policy,
        &params,
        &pubkey,
        &pubkey_size,
        &pubkey_info,
        &pubkey_info_size);

    if (ret != OE_OK)
        return -1;

    // Copy to host memory.
    ret = oe_memcpy_s(keybuf, keybuf_maxsize, pubkey, pubkey_size);
    if (ret != OE_OK)
        return -1;

    ret = oe_memcpy_s(keyinfo, keyinfo_maxsize, pubkey_info, pubkey_info_size);
    if (ret != OE_OK)
        return -1;

    *keybuf_size = pubkey_size;
    *keyinfo_size = pubkey_info_size;

    oe_free_key(pubkey, pubkey_size, pubkey_info, pubkey_info_size);
    return 0;
}

int enc_get_public_key(
    const char* data,
    const uint8_t* keyinfo,
    size_t keyinfo_size,
    uint8_t* keybuf,
    size_t keybuf_maxsize,
    size_t* keybuf_size)
{
    oe_asymmetric_key_params_t params;
    oe_result_t ret;
    uint8_t* pubkey = NULL;
    size_t pubkey_size = 0;

    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = (void*)data;
    params.user_data_size = data ? strlen(data) : 0;

    ret = oe_get_public_key(
        &params, keyinfo, keyinfo_size, &pubkey, &pubkey_size);

    if (ret != OE_OK)
        return -1;

    // Copy to host memory.
    ret = oe_memcpy_s(keybuf, keybuf_maxsize, pubkey, pubkey_size);
    if (ret != OE_OK)
        return -1;

    *keybuf_size = pubkey_size;

    oe_free_key(pubkey, pubkey_size, NULL, 0);
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    256,  /* NumHeapPages */
    64,   /* NumStackPages */
    5);   /* NumTCS */
