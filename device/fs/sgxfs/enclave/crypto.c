// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include "common.h"
#include "sgx_error.h"
#include "sgx_tcrypto.h"
#include <mbedtls/gcm.h>
#include <mbedtls/cmac.h>
// clang-format on

sgx_status_t SGXAPI sgx_rijndael128GCM_encrypt(
    const sgx_aes_gcm_128bit_key_t* p_key,
    const uint8_t* p_src,
    uint32_t src_len,
    uint8_t* p_dst,
    const uint8_t* p_iv,
    uint32_t iv_len,
    const uint8_t* p_aad,
    uint32_t aad_len,
    sgx_aes_gcm_128bit_tag_t* p_out_mac)
{
    sgx_status_t err = 0;
    mbedtls_gcm_context gcm;

    mbedtls_gcm_init(&gcm);

    if (mbedtls_gcm_setkey(
            &gcm, MBEDTLS_CIPHER_ID_AES, (unsigned char*)p_key, 128) != 0)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    if (mbedtls_gcm_crypt_and_tag(
            &gcm,
            MBEDTLS_GCM_ENCRYPT,
            src_len,
            p_iv,
            iv_len,
            p_aad,
            aad_len,
            p_src,
            p_dst,
            sizeof(sgx_aes_gcm_128bit_tag_t),
            (unsigned char*)p_out_mac) != 0)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

done:

    mbedtls_gcm_free(&gcm);

    return err;
}

sgx_status_t SGXAPI sgx_rijndael128GCM_decrypt(
    const sgx_aes_gcm_128bit_key_t* p_key,
    const uint8_t* p_src,
    uint32_t src_len,
    uint8_t* p_dst,
    const uint8_t* p_iv,
    uint32_t iv_len,
    const uint8_t* p_aad,
    uint32_t aad_len,
    const sgx_aes_gcm_128bit_tag_t* p_in_mac)
{
    sgx_status_t err = 0;
    mbedtls_gcm_context gcm;

    mbedtls_gcm_init(&gcm);

    if (mbedtls_gcm_setkey(
            &gcm, MBEDTLS_CIPHER_ID_AES, (unsigned char*)p_key, 128) != 0)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    if (mbedtls_gcm_auth_decrypt(
            &gcm,
            src_len,
            p_iv,
            iv_len,
            p_aad,
            aad_len,
            (const unsigned char*)p_in_mac,
            16,
            p_src,
            p_dst) != 0)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

done:

    mbedtls_gcm_free(&gcm);

    return err;
}

sgx_status_t SGXAPI sgx_rijndael128_cmac_msg(
    const sgx_cmac_128bit_key_t* p_key,
    const uint8_t* p_src,
    uint32_t src_len,
    sgx_cmac_128bit_tag_t* p_mac)
{
    sgx_status_t err = 0;
    const mbedtls_cipher_info_t* info;

    if (!(info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)))
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    if (mbedtls_cipher_cmac(
            info,
            (const unsigned char*)p_key,
            128,
            p_src,
            src_len,
            (unsigned char*)p_mac) != 0)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

done:
    return err;
}
