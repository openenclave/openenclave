// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/bits/stdio.h>

// Include the trusted helloworld header that is generated
// during the build. This file is generated by calling the
// sdk tool sgx_edger8r against the SimSecTempSensor.edl file.
#include "SimSecTempSensor_t.h"

#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/sha256.h>

int oe_random_wrapper(void* param, unsigned char* buffer, size_t len)
{
    return oe_random(buffer, len);
}

// This function generates SHA256 hash of the given data
static int mbedtls_sha256_hash(
    unsigned char* output,
    const unsigned char* input,
    const size_t input_size)
{
    int ret = 0;
    mbedtls_sha256_context sha256;

    mbedtls_sha256_init(&sha256);

    mbedtls_sha256_update(&sha256, input, input_size);

    mbedtls_sha256_finish(&sha256, output);

    mbedtls_sha256_free(&sha256);

    return ret;
}

// This functions generates a signature for the given data using the TA private key
int generate_signature(
    uint8_t* data, 
    size_t data_size, 
    uint8_t* signature,
    size_t signature_size,
    size_t* signature_size_needed)
{
    mbedtls_pk_context key_ctx = {0};
    uint8_t* key_buf = NULL;
    size_t key_buf_size;

    oe_result_t result = oe_get_private_key(NULL, 0, &key_buf, &key_buf_size);
    if (result != OE_OK)
    {
        goto exit;
    }

    int ret = mbedtls_pk_parse_key(&key_ctx, key_buf, key_buf_size, NULL, 0);
    if (ret != 0)
    {
        result = OE_FAILURE;
        goto exit;
    }

    {
        uint8_t hash[32];
        mbedtls_sha256_hash(hash, data, data_size);

        *signature_size_needed = signature_size;
        ret = mbedtls_pk_sign(
            &key_ctx,
            MBEDTLS_MD_SHA256,
            hash, 
            sizeof(hash), 
            signature, 
            signature_size_needed,
            oe_random_wrapper, 
            NULL);
        if (ret != 0)
        {
            result = OE_FAILURE;
            goto exit;
        }

        if (signature_size < *signature_size_needed)
        {
            result = OE_FAILURE;
            goto exit;
        }
    }

exit: 
    if (key_buf)
    {
        oe_free_key(key_buf, NULL);
    }

    return result;
}

// This function returns current sensor value and a signature 
// based on the private key belonging to the TA.
int enclave_readsensor(
    uint32_t* value, 
    uint8_t* signature_buffer, 
    size_t signature_buffer_size, 
    size_t* signature_buffer_used)
{
    // Simulate reading from a sensor using trusted IO
    oe_result_t result = oe_random(value, sizeof(*value));
    if (result != OE_OK)
    {
        return result;
    }

    // Make it look more like a temperature
    *value %= 99;

    result = generate_signature((uint8_t*)value, sizeof(*value), signature_buffer, signature_buffer_size, signature_buffer_used);
    if (result != OE_OK)
    {
        return result;
    }

    return OE_OK;
}
