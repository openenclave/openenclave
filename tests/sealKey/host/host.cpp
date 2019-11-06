// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "sealKey_u.h"

#define SKIP_RETURN_CODE 2

static int _test_single_key(
    uint32_t policy,
    oe_enclave_t* enclave,
    const char* data)
{
    uint8_t key[1024];
    size_t keysize = 1024;
    uint8_t* key2 = NULL;
    size_t key2size = 0;
    uint8_t key3[1024];
    size_t key3size = 1024;
    uint8_t* key4 = NULL;
    size_t key4size = 0;
    uint8_t keyinfo[1024];
    size_t keyinfo_size = 1024;
    uint8_t* keyinfo2 = NULL;
    size_t keyinfo2_size = 0;
    oe_result_t result;
    oe_asymmetric_key_params_t params;
    int ret;

    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = (void*)data;
    params.user_data_size = data ? strlen(data) : 0;

    // Check if key and keyinfo match with the enclave version
    result = enc_get_public_key_by_policy(
        enclave,
        &ret,
        (int)policy,
        data,
        key,
        keysize,
        &keysize,
        keyinfo,
        keyinfo_size,
        &keyinfo_size);

    if (result != OE_OK)
    {
        oe_put_err("enc_get_public_key_by_policy(): result=%u", result);
        return -1;
    }

    result = oe_get_public_key_by_policy(
        enclave,
        (oe_seal_policy_t)policy,
        &params,
        &key2,
        &key2size,
        &keyinfo2,
        &keyinfo2_size);

    if (result != OE_OK)
    {
        oe_put_err("oe_get_public_key_by_policy(): result=%u", result);
        return -1;
    }

    // The host and the enclave side should return the same values.
    if (keysize != key2size || memcmp(key, key2, keysize) != 0)
    {
        oe_put_err("enclave and host public keys different");
        return -1;
    }

    if (keyinfo_size != keyinfo2_size ||
        memcmp(keyinfo, keyinfo2, keyinfo_size) != 0)
    {
        oe_put_err("enclave and host key info different");
        return -1;
    }

    // Do the same test with the other API.
    result = enc_get_public_key(
        enclave, &ret, data, keyinfo, keyinfo_size, key3, key3size, &key3size);

    if (result != OE_OK)
    {
        oe_put_err("enc_get_public_key(): result=%u", result);
        return -1;
    }

    result = oe_get_public_key(
        enclave, &params, keyinfo2, keyinfo2_size, &key4, &key4size);

    if (result != OE_OK)
    {
        oe_put_err("oe_get_public_key_by_policy(): result=%u", result);
        return -1;
    }

    // The host and the enclave side should return the same values.
    if (key3size != key4size || memcmp(key3, key4, key3size) != 0)
    {
        oe_put_err("enclave and host public keys different");
        return -1;
    }

    // Both APIs on the host side should also return the same value.
    if (key2size != key4size || memcmp(key2, key4, key2size) != 0)
    {
        oe_put_err("host public key APIs return different keys");
        return -1;
    }

    oe_free_key(key2, key2size, keyinfo2, keyinfo2_size);
    oe_free_key(key4, key4size, NULL, 0);
    return 0;
}

static void test_host_public_key(oe_enclave_t* enclave)
{
    // Loop through the policies.
    for (uint32_t seal_policy = OE_SEAL_POLICY_UNIQUE;
         seal_policy <= OE_SEAL_POLICY_PRODUCT;
         seal_policy++)
    {
        // Test with NULL user data.
        _test_single_key(seal_policy, enclave, NULL);

        // Test with empty string.
        _test_single_key(seal_policy, enclave, "");

        // Test with custom user data.
        _test_single_key(seal_policy, enclave, "asd");
        _test_single_key(seal_policy, enclave, "longgggggg----striggggggg\n");
    }
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode (sealKey)\n");
        return SKIP_RETURN_CODE;
    }

    printf("=== This program is used to test enclave seal key functions.\n");

    result = oe_create_sealKey_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_create_sealKey_enclave(): result=%u", result);
        return 1;
    }

    int retval = -1;
    result = test_seal_key(enclave, &retval, retval);
    OE_TEST(result == OE_OK);
    OE_TEST(retval == 0);

    test_host_public_key(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
        return 1;
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
