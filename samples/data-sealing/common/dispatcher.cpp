// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <stdio.h>
#include <string.h>
#include "common.h"

ecall_dispatcher::ecall_dispatcher()
{
    m_data = NULL;
    m_data_size = 0;
    m_sealed_data = NULL;
    init_mbedtls();
}

ecall_dispatcher::~ecall_dispatcher()
{
    cleanup_mbedtls();
}

void ecall_dispatcher::init_mbedtls()
{
    const char pers[] = "random data string";
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_ctr_drbg_init(&m_ctr_drbg_contex);

    // mbedtls_ctr_drbg_seed seeds and sets up the CTR_DRBG entropy source for
    // future reseeds.
    mbedtls_ctr_drbg_seed(
        &m_ctr_drbg_contex,
        mbedtls_entropy_func,
        &m_entropy_context,
        (unsigned char*)pers,
        sizeof(pers));
}

void ecall_dispatcher::cleanup_mbedtls(void)
{
    mbedtls_entropy_free(&m_entropy_context);
    mbedtls_ctr_drbg_free(&m_ctr_drbg_contex);
}

int ecall_dispatcher::seal_data(
    int seal_policy,
    unsigned char* opt_mgs,
    size_t opt_msg_len,
    unsigned char* data,
    size_t data_size,
    sealed_data_t** sealed_data,
    size_t* sealed_data_size)
{
    oe_result_t result = OE_OK;
    int ret = 0;
    unsigned char iv[IV_SIZE];
    sealed_data_t* temp_sealed_data = NULL;

    uint8_t* seal_key = NULL;
    size_t seal_key_size = 0;

    // get seal key and allocate sealed_data_t structure and initialize with
    // basic information
    result = get_seal_key_and_prep_sealed_data(
        seal_policy,
        data,
        data_size,
        opt_mgs,
        opt_msg_len,
        &seal_key,
        &seal_key_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE(
            "get_seal_key_and_prep_sealed_data failed with %s\n",
            oe_result_str(result));
        goto exit;
    }

    // generate random initialization vector values
    TRACE_ENCLAVE("generate random initialization vector values");
    ret = generate_iv(m_sealed_data->iv, IV_SIZE);
    if (ret != 0)
    {
        TRACE_ENCLAVE("generate_iv failed with %d", ret);
        goto exit;
    }
    memcpy(iv, m_sealed_data->iv, IV_SIZE);

    // We need to cast these variables down to unsigned int.
    // Check if that will cut off any significant bits.
    if (m_data_size > UINT32_MAX)
    {
        TRACE_ENCLAVE("m_data_size is too large to fit into an unsigned int");
        goto exit;
    }
    if (seal_key_size > UINT32_MAX)
    {
        TRACE_ENCLAVE("seal_key_size is too large to fit into an unsigned int");
        goto exit;
    }

    // seal data: encrypt data with the seal key
    ret = cipher_data(
        ENCRYPT_OPERATION,
        m_data,
        (unsigned int)m_data_size,
        seal_key,
        (unsigned int)seal_key_size,
        iv,
        m_sealed_data->encrypted_data);
    if (ret != 0)
    {
        TRACE_ENCLAVE("cipher_data failed with %d\n", ret);
        goto exit;
    }

    // On the return from above cipher_data, the iv value was updated ,
    // initialize to the original value before using it in sign_sealed_data
    memcpy(iv, m_sealed_data->iv, IV_SIZE);

    // generate signature by signing the hash of the sealed data with the seal
    // key
    ret = sign_sealed_data(
        m_sealed_data,
        seal_key,
        (unsigned int)seal_key_size,
        m_sealed_data->signature);
    if (ret != 0)
    {
        TRACE_ENCLAVE("sign_sealed_data %d\n", ret);
        goto exit;
    }

    temp_sealed_data =
        (sealed_data_t*)oe_host_malloc(m_sealed_data->total_size);
    if (temp_sealed_data == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto exit;
    }
    memcpy(temp_sealed_data, m_sealed_data, m_sealed_data->total_size);

    *sealed_data_size = m_sealed_data->total_size;
    *sealed_data = temp_sealed_data;
exit:

    if (m_data)
    {
        free(m_data);
        m_data = NULL;
    }

    if (seal_key)
        free(seal_key);

    if (m_sealed_data)
    {
        free(m_sealed_data);
        m_sealed_data = NULL;
    }

    if (ret)
        result = OE_FAILURE;
    return (int)result;
}

int ecall_dispatcher::unseal_data(
    sealed_data_t* sealed_data,
    size_t sealed_data_size,
    unsigned char** data,
    size_t* data_size)
{
    oe_result_t result = OE_OK;
    unsigned char iv[IV_SIZE];
    unsigned char signature[SIGNATURE_LEN];
    uint8_t* seal_key = NULL;
    size_t seal_key_size = 0;
    uint8_t* key_info = NULL;
    size_t key_info_size = 0;

    unsigned char* data_buf = NULL;
    int ret = 0;

    key_info = sealed_data->encrypted_data + sealed_data->encrypted_data_len;
    key_info_size = sealed_data->key_info_size;

    m_sealed_data = sealed_data;
    *data_size = 0;
    *data = NULL;

    if (sealed_data_size != sealed_data->total_size)
    {
        TRACE_ENCLAVE(
            "Seal data does not match the seal data size. Expected %zd, got: "
            "%zd",
            sealed_data->total_size,
            sealed_data_size);
        ret = ERROR_INVALID_PARAMETER;
        goto exit;
    }
    // retrieve the seal key
    result = get_seal_key_by_keyinfo(
        key_info, key_info_size, &seal_key, &seal_key_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("unseal_data failed with %sn", oe_result_str(result));
        ret = ERROR_GET_SEALKEY;
        goto exit;
    }

    // We need to cast these variables down to unsigned int.
    // Check if that will cut off any significant bits.
    if (m_sealed_data->encrypted_data_len > UINT32_MAX)
    {
        TRACE_ENCLAVE("seal_key_size is too large to fit into an unsigned int");
        goto exit;
    }
    if (seal_key_size > UINT32_MAX)
    {
        TRACE_ENCLAVE("seal_key_size is too large to fit into an unsigned int");
        goto exit;
    }

    // validate signature by re-generating a signature from the input
    // sealed_data
    // structure then comparing it with sealed_data.signature

    // regenerate signature
    ret = sign_sealed_data(
        m_sealed_data, seal_key, (unsigned int)seal_key_size, signature);
    if (ret != 0)
    {
        ret = ERROR_SIGN_SEALED_DATA_FAIL;
        TRACE_ENCLAVE("sign_sealed_data failed with %d", ret);
        goto exit;
    }

    // validate signature
    if (memcmp(signature, m_sealed_data->signature, SIGNATURE_LEN) != 0)
    {
        TRACE_ENCLAVE("signature mismatched");
        ret = ERROR_SIGNATURE_VERIFY_FAIL;
        goto exit;
    }
    TRACE_ENCLAVE("signature validation passed successfully");

    // Unseal data: decrypt data with the seal key
    // re-initialization vector values
    memcpy(iv, m_sealed_data->iv, sizeof(iv));

    data_buf =
        (unsigned char*)oe_host_malloc(m_sealed_data->encrypted_data_len);
    if (data_buf == NULL)
    {
        ret = ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    ret = cipher_data(
        DECRYPT_OPERATION,
        m_sealed_data->encrypted_data,
        (unsigned int)m_sealed_data->encrypted_data_len,
        seal_key,
        (unsigned int)seal_key_size,
        iv,
        data_buf);
    if (ret != 0)
    {
        TRACE_ENCLAVE("cipher_data failed with %d\n", ret);
        ret = ERROR_CIPHER_ERROR;
        goto exit;
    }

    *data_size = m_sealed_data->original_data_size;
    *data = data_buf;

exit:
    if (seal_key)
        free(seal_key);

    return ret;
}

oe_result_t ecall_dispatcher::get_seal_key_and_prep_sealed_data(
    int seal_policy,
    unsigned char* data,
    size_t data_size,
    unsigned char* opt_mgs,
    size_t opt_msg_len,
    uint8_t** seal_key,
    size_t* seal_key_size)
{
    oe_result_t result = OE_OK;
    size_t bytes_left = 0;
    size_t total_size = 0;
    size_t original_data_size = 0;
    uint8_t* key_info;
    size_t key_info_size;
    unsigned char* padded_data = NULL;
    size_t padded_byte_count = 0;

    // retrieve the seal key
    result = get_seal_key_by_policy(
        seal_policy, seal_key, seal_key_size, &key_info, &key_info_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE(
            "get_seal_key_by_policy failed with %s", oe_result_str(result));
        goto exit;
    }
    TRACE_ENCLAVE("seal_key_size  %ld", *seal_key_size);
    TRACE_ENCLAVE("key_info_size  %ld", key_info_size);
    TRACE_ENCLAVE("data_size  %ld", data_size);

    m_data = data;
    m_data_size = data_size;
    original_data_size = data_size;

    // cbc encryption used in this sample required CIPHER_BLOCK_SIZE alignment
    // update the data and its size if padding is needed
    bytes_left = m_data_size % CIPHER_BLOCK_SIZE;

    // PKCS5 padding
    // if the original data size is an integer multiple of blocks
    // pad n extra block of bytes with value N is added
    if (bytes_left == 0)
        padded_byte_count = CIPHER_BLOCK_SIZE;
    else
        padded_byte_count = CIPHER_BLOCK_SIZE - bytes_left;

    if (padded_byte_count > UINT32_MAX)
    {
        TRACE_ENCLAVE("padded_byte_count is too large to fit into an int");
        goto exit;
    }

    padded_data = (unsigned char*)malloc(m_data_size + padded_byte_count);
    if (padded_data == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto exit;
    }
    memset((void*)padded_data, 0, m_data_size + padded_byte_count);
    // prepare new data buffer if padding is needed
    memcpy((void*)padded_data, (void*)m_data, m_data_size);
    // PKCS5 padding
    memset(
        (void*)(padded_data + m_data_size),
        (int)padded_byte_count,
        padded_byte_count);
    m_data_size += padded_byte_count;

    // update data with new padded memory
    m_data = padded_data;

    total_size = sizeof(sealed_data_t) + m_data_size + key_info_size;

    // allocate the sealed data buffer inside enclave and fill with metadata
    // information
    m_sealed_data = (sealed_data_t*)malloc(total_size);
    if (m_sealed_data == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto exit;
    }

    m_sealed_data->key_info_size = key_info_size;
    m_sealed_data->total_size = total_size;
    memcpy(m_sealed_data->opt_msg, opt_mgs, opt_msg_len);
    m_sealed_data->encrypted_data_len = m_data_size;
    m_sealed_data->original_data_size = original_data_size;

    // copy key info into the sealed_data_t
    memcpy(
        (void*)(m_sealed_data->encrypted_data + m_sealed_data->encrypted_data_len),
        (void*)key_info,
        key_info_size);
exit:
    if (key_info)
        free(key_info);

    return result;
}
