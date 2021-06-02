// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/gcm.h>
#include <openenclave/internal/entropy.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>
#include <openenclave/sgx/seal.h>
#include <stdlib.h>

#include "report.h"

struct _sealed_blob_header
{
    sgx_key_request_t keyrequest;
    uint32_t ciphertext_size;
    uint8_t reserved[12];
    uint32_t total_size;
    uint8_t iv[12];
    uint8_t tag[16];
};

static oe_result_t _init_key_request(sgx_key_request_t* keyrequest)
{
    sgx_report_t report = {{{0}}};

    oe_result_t result = OE_OK;

    OE_CHECK(
        oe_memset_s(keyrequest, sizeof(*keyrequest), 0, sizeof(*keyrequest)));

    OE_CHECK(sgx_create_report(NULL, 0, NULL, 0, &report));
    OE_CHECK(oe_memcpy_s(
        &keyrequest->cpu_svn,
        sizeof(keyrequest->cpu_svn),
        &report.body.cpusvn,
        sizeof(report.body.cpusvn)));

    keyrequest->key_name = SGX_KEYSELECT_SEAL;
    keyrequest->key_policy = SGX_KEYPOLICY_MRSIGNER;
    keyrequest->isv_svn = report.body.isvsvn;
    keyrequest->attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    keyrequest->attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
    keyrequest->misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;

done:
    return result;
}

static oe_result_t _seal(
    const oe_seal_setting_t* settings,
    size_t settings_count,
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    oe_result_t result = OE_OK;
    struct _sealed_blob_header* header;
    uint8_t* key = NULL;
    size_t size;
    oe_entropy_kind_t kind;
    size_t i;

    size = sizeof(*header);
    if (plaintext_size > OE_UINT32_MAX - size)
        return OE_INTEGER_OVERFLOW;
    size += plaintext_size;
    if (additional_data_size > OE_UINT32_MAX - size)
        return OE_INTEGER_OVERFLOW;
    // Please note that blob will NOT include additional_data

    *blob_size = size;
    *blob = (uint8_t*)oe_calloc(1, size);
    if (*blob == NULL)
        return OE_OUT_OF_MEMORY;

    header = (struct _sealed_blob_header*)*blob;
    OE_CHECK(_init_key_request(&header->keyrequest));
    OE_CHECK(oe_get_entropy(
        header->keyrequest.key_id, sizeof(header->keyrequest.key_id), &kind));
    header->ciphertext_size = (uint32_t)plaintext_size;
    header->total_size = (uint32_t)(plaintext_size + additional_data_size);
    OE_CHECK(oe_get_entropy(header->iv, sizeof(header->iv), &kind));

    for (i = 0; i < settings_count; ++i)
        switch (settings[i].type)
        {
            case OE_SEAL_SETTING_POLICY:
                switch (settings[i].value.w)
                {
                    case OE_SEAL_POLICY_UNIQUE:
                        header->keyrequest.key_policy = SGX_KEYPOLICY_MRENCLAVE;
                        break;
                    case OE_SEAL_POLICY_PRODUCT:
                        header->keyrequest.key_policy = SGX_KEYPOLICY_MRSIGNER;
                        break;
                    default:
                        OE_RAISE(OE_INVALID_PARAMETER);
                }
                break;

            case OE_SEAL_SETTING_IV:
                if (settings[i].size != sizeof(header->iv))
                    OE_RAISE(OE_INVALID_PARAMETER);
                else
                    OE_CHECK(oe_memcpy_s(
                        header->iv,
                        sizeof(header->iv),
                        settings[i].value.p,
                        settings[i].size));
                break;

            case OE_SEAL_SETTING_SGX_KEYNAME:
                header->keyrequest.key_name = settings[i].value.w;
                break;

            case OE_SEAL_SETTING_SGX_ISVSVN:
                header->keyrequest.isv_svn = settings[i].value.w;
                break;

            case OE_SEAL_SETTING_SGX_CPUSVN:
                if (settings[i].size != sizeof(header->keyrequest.cpu_svn))
                    OE_RAISE(OE_INVALID_PARAMETER);
                OE_CHECK(oe_memcpy_s(
                    header->keyrequest.cpu_svn,
                    sizeof(header->keyrequest.cpu_svn),
                    settings[i].value.p,
                    settings[i].size));
                break;

            case OE_SEAL_SETTING_SGX_FLAGSMASK:
                header->keyrequest.attribute_mask.flags = settings[i].value.q;
                break;

            case OE_SEAL_SETTING_SGX_XFRMMASK:
                header->keyrequest.attribute_mask.xfrm = settings[i].value.q;
                break;

            case OE_SEAL_SETTING_SGX_MISCMASK:
                header->keyrequest.misc_attribute_mask = settings[i].value.d;
                break;

            case OE_SEAL_SETTING_SGX_CONFIGSVN:
                header->keyrequest.config_svn = settings[i].value.w;
                break;

            case OE_SEAL_SETTING_ADDITIONAL_CONTEXT:
                // Custom OE_SEAL_SETTING_ADDITIONAL_CONTEXT not supported

            case OE_SEAL_SETTING_SGX_CET_ATTRIBUTES_MASK:
                // OE_SEAL_SETTING_SGX_CET_ATTRIBUTES_MASK not supported

            default:
                OE_RAISE(OE_UNSUPPORTED);
        }

    OE_CHECK(oe_get_seal_key(
        (uint8_t*)&header->keyrequest,
        sizeof(header->keyrequest),
        &key,
        &size));

    OE_STATIC_ASSERT(sizeof(header->tag) >= 16);
    OE_CHECK(oe_aes_gcm_encrypt(
        key,
        size,
        header->iv,
        sizeof(header->iv),
        additional_data,
        additional_data_size,
        plaintext,
        plaintext_size,
        (uint8_t*)(header + 1),
        header->tag));

done:
    oe_free_key(key, size, NULL, 0);

    if (result != OE_OK)
    {
        oe_free(*blob);
        *blob = NULL;
    }

    return result;
}

static oe_result_t _unseal(
    const uint8_t* blob,
    size_t blob_size,
    const uint8_t* additional_data,
    size_t additional_data_size,
    uint8_t** plaintext,
    size_t* plaintext_size)
{
    oe_result_t result = OE_OK;
    struct _sealed_blob_header* header = (struct _sealed_blob_header*)blob;
    uint8_t* key = NULL;
    size_t key_size = 0;

    if (blob_size < sizeof(*header))
        return OE_INVALID_PARAMETER;

    if (header->ciphertext_size != blob_size - sizeof(*header) ||
        header->total_size != header->ciphertext_size + additional_data_size)
        return OE_CRYPTO_ERROR;

    *plaintext_size = header->ciphertext_size;
    *plaintext = (uint8_t*)oe_calloc(1, *plaintext_size);
    if (*plaintext == NULL)
        return OE_OUT_OF_MEMORY;

    OE_CHECK(oe_get_seal_key(
        (uint8_t*)&header->keyrequest,
        sizeof(header->keyrequest),
        &key,
        &key_size));

    OE_CHECK(oe_aes_gcm_decrypt(
        key,
        key_size,
        header->iv,
        sizeof(header->iv),
        additional_data,
        additional_data_size,
        (uint8_t*)(header + 1),
        header->ciphertext_size,
        *plaintext,
        header->tag));

done:
    oe_free_key(key, key_size, NULL, 0);

    if (result != OE_OK)
    {
        oe_free(*plaintext);
        *plaintext = NULL;
    }

    return result;
}

const oe_seal_plugin_definition_t oe_seal_plugin_gcm_aes = {
    {{0xb3,
      0x38,
      0xde,
      0xea,
      0x4c,
      0x9b,
      0x41,
      0x88,
      0x90,
      0x00,
      0x50,
      0x5b,
      0x8f,
      0x63,
      0xf7,
      0x6f}},
    _seal,
    _unseal};

__attribute__((constructor)) static void _register_seal_plugin(void)
{
    oe_register_seal_plugin(&oe_seal_plugin_gcm_aes, false);
}
