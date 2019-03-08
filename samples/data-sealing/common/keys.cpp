// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include "common.h"
#include "dispatcher.h"

void ecall_dispatcher::dump_data(
    const char* name,
    unsigned char* data,
    size_t data_size)
{
    TRACE_ENCLAVE("Data name: %s:", name);
    for (size_t i = 0; i < data_size; i++)
    {
        TRACE_ENCLAVE("[%ld]-0x%02X", i, data[i]);
    }
    TRACE_ENCLAVE("\n");
}

// Generate initialization vector (IV), which will be used along with a key for
// data encryption
int ecall_dispatcher::generate_iv(unsigned char* iv, unsigned int ivLen)
{
    int ret = 0;

    memset(iv, 0, ivLen);
    // mbedtls_ctr_drbg_random uses CTR_DRBG to generate random data
    ret = mbedtls_ctr_drbg_random(&m_ctr_drbg_contex, iv, ivLen);
    return ret;
}

int ecall_dispatcher::cipher_data(
    bool encrypt,
    unsigned char* input_data,
    unsigned int input_data_size,
    unsigned char* key,
    unsigned int key_size,
    unsigned char* iv,
    unsigned char* output_data)
{
    int ret = 0;
    unsigned char local_iv[IV_SIZE];
    mbedtls_aes_context aescontext;

    memcpy(local_iv, iv, IV_SIZE);
    // init context
    mbedtls_aes_init(&aescontext);

    // set aes key
    if (encrypt)
        ret = mbedtls_aes_setkey_enc(&aescontext, key, key_size * 8);
    else
        ret = mbedtls_aes_setkey_dec(&aescontext, key, key_size * 8);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_setkey_enc failed with %d", ret);
        goto exit;
    }

    // start ciphering operation
    ret = mbedtls_aes_crypt_cbc(
        &aescontext,
        encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        input_data_size, // input data length in bytes,
        local_iv,        // Initialization vector (updated after use)
        input_data,
        output_data);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_crypt_cbc failed with %d", ret);
        goto exit;
    }
exit:
    // free aes context
    mbedtls_aes_free(&aescontext);
    return ret;
}

// Get a seal key based on the input policy.
// Note: Different platforms might support seal key with different key size and
// keyinfo, that's why required buffer size queries were done in this routine.
// See oe_get_seal_key_by_policy for more details
oe_result_t ecall_dispatcher::get_seal_key_by_policy(
    int policy,
    uint8_t** key_buf,
    size_t* key_buf_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    oe_result_t result = OE_OK;
    uint8_t* buf = NULL;
    size_t buf_size = 0;
    uint8_t* info = NULL;
    size_t info_size = 0;

    TRACE_ENCLAVE("get_seal_key_by_policy: %d", policy);

    result = oe_get_seal_key_by_policy(
        (oe_seal_policy_t)policy, &buf, &buf_size, &info, &info_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE(
            "oe_get_seal_key_by_policy failed with %s\n",
            oe_result_str(result));
        goto exit;
    }

    // fill the return information
    *key_buf = buf;
    *key_buf_size = buf_size;

    *key_info = info;
    *key_info_size = info_size;
exit:
    if (result != OE_OK)
    {
        if (buf && info)
            oe_free_key(buf, buf_size, info, info_size);
    }
    return result;
}

oe_result_t ecall_dispatcher::get_seal_key_by_keyinfo(
    uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buf,
    size_t* key_buf_size)
{
    oe_result_t result = OE_OK;
    uint8_t* buf = NULL;
    size_t required_buf_size = 0;

    result = oe_get_seal_key(key_info, key_info_size, &buf, &required_buf_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE(
            "oe_get_seal_key_by_policy failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
    *key_buf = buf;
    *key_buf_size = required_buf_size;

exit:
    if (result != OE_OK)
    {
        if (buf)
            oe_free_key(key_info, key_info_size, buf, required_buf_size);
    }
    return result;
}

int ecall_dispatcher::sign_sealed_data(
    sealed_data_t* sealed_data,
    unsigned char* key,
    unsigned int key_size,
    unsigned char* signature)
{
    int ret = 0;
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    TRACE_ENCLAVE("sign_sealed_data");

    ret = mbedtls_md_setup(
        &ctx, mbedtls_md_info_from_type(md_type), 1); // use hmac
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_starts(&ctx, key, key_size);
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx, (const unsigned char*)&(sealed_data->total_size), sizeof(size_t));
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)sealed_data->opt_msg,
        strlen((const char*)sealed_data->opt_msg));
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx, (const unsigned char*)sealed_data->iv, IV_SIZE);
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)&(sealed_data->original_data_size),
        sizeof(size_t));
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)&(sealed_data->key_info_size),
        sizeof(size_t));
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)&(sealed_data->encrypted_data_len),
        sizeof(size_t));
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_update(
        &ctx,
        (const unsigned char*)sealed_data->encrypted_data,
        sealed_data->encrypted_data_len + sealed_data->key_info_size);
    if (ret)
        goto exit;

    ret = mbedtls_md_hmac_finish(&ctx, signature);

exit:
    mbedtls_md_free(&ctx);
    return ret;
}
