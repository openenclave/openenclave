// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdint.h>
#include <stdio.h>

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/crypto/gcm.h>
#include <openenclave/internal/raise.h>
#include <openenclave/seal.h>

#include "report.h"

#include "oeseal_t.h"

#define POLICY_UNIQUE 1

/* Copy from enclave/sealing/sgx/seal_gcmaes.c for debugging purposes */
typedef struct _sealed_blob_header_t
{
    sgx_key_request_t keyrequest;
    uint32_t ciphertext_size;
    uint8_t reserved[12];
    uint32_t total_size;
    uint8_t iv[12];
    uint8_t tag[OE_GCM_TAG_SIZE];
} sealed_blob_header_t;

static oe_result_t _get_default_key_request(sgx_key_request_t* keyrequest)
{
    sgx_report_t report = {0};
    oe_result_t result = OE_FAILURE;

    memset(keyrequest, 0, sizeof(*keyrequest));

    OE_CHECK(sgx_create_report(NULL, 0, NULL, 0, &report));

    memcpy(
        &keyrequest->cpu_svn, &report.body.cpusvn, sizeof(report.body.cpusvn));

    keyrequest->key_name = SGX_KEYSELECT_SEAL;
    keyrequest->key_policy = SGX_KEYPOLICY_MRSIGNER;
    keyrequest->isv_svn = report.body.isvsvn;
    keyrequest->attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK;
    keyrequest->attribute_mask.xfrm = OE_SEALKEY_DEFAULT_XFRMMASK;
    keyrequest->misc_attribute_mask = OE_SEALKEY_DEFAULT_MISCMASK;

    result = OE_OK;

done:
    return result;
}

static void _dump_hex(char* key, uint8_t* data, size_t size)
{
    printf("%s: ", key);
    for (size_t i = 0; i < size; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static oe_result_t _dump_sgx_key_request(sgx_key_request_t* key_request)
{
    oe_result_t result = OE_FAILURE;

    if (!key_request)
        OE_RAISE(OE_INVALID_PARAMETER);

    printf("key_name: %x\n", key_request->key_name);
    printf("key_policy: %x\n", key_request->key_policy);
    printf("isv_svn: %x\n", key_request->isv_svn);
    _dump_hex("cpu_svn", key_request->cpu_svn, SGX_CPUSVN_SIZE);
    printf("attribute_mask flags: %lx\n", key_request->attribute_mask.flags);
    printf("attribute_mask xfrm: %lx\n", key_request->attribute_mask.xfrm);
    _dump_hex("key_id", key_request->key_id, SGX_KEYID_SIZE);
    printf("misc_attribute_mask: %lx\n", key_request->misc_attribute_mask);
    printf("config_svn: %x\n", key_request->config_svn);

done:
    return result;
}

static oe_result_t _dump_sealed_blob_header(sealed_blob_header_t* header)
{
    oe_result_t result = OE_FAILURE;

    if (!header)
        OE_RAISE(OE_INVALID_PARAMETER);

    _dump_sgx_key_request(&header->keyrequest);
    printf("ciphertext_size: %lu\n", header->ciphertext_size);
    printf("total_size: %lu\n", header->total_size);
    _dump_hex("iv", header->iv, 12);
    _dump_hex("tag", header->tag, OE_GCM_TAG_SIZE);

done:
    return result;
}

static oe_result_t _dump_enclave_identities()
{
    oe_result_t result = OE_FAILURE;
    sgx_report_t report = {0};

    OE_CHECK(sgx_create_report(NULL, 0, NULL, 0, &report));

    printf("Enclave Identities:\n");
    _dump_hex("mrenclave", report.body.mrenclave, OE_SHA256_SIZE);
    _dump_hex("mrsigner", report.body.mrsigner, OE_SHA256_SIZE);

    result = OE_OK;

done:
    return result;
}

oe_result_t enc_seal(uint8_t* data, size_t size, output_t* output, bool verbose)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* blob = NULL;
    size_t blob_size = 0;

    if (!data || !size || !output)
        OE_RAISE(OE_INVALID_PARAMETER);

    const oe_seal_setting_t settings[] = {OE_SEAL_SET_POLICY(POLICY_UNIQUE)};
    OE_CHECK(oe_seal(
        NULL,
        settings,
        sizeof(settings) / sizeof(*settings),
        data,
        size,
        NULL,
        0,
        &blob,
        &blob_size));

    if (blob_size > UINT32_MAX)
    {
        OE_TRACE_ERROR("blob_size is too large to fit into an unsigned int");
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    if (verbose)
    {
        _dump_enclave_identities();

        if (blob_size > sizeof(sealed_blob_header_t))
        {
            sealed_blob_header_t* header = (sealed_blob_header_t*)blob;

            printf("Sealed blob header:\n");

            _dump_sealed_blob_header(header);

            printf(
                "blob_size: %zu, expected: %zu (header %zu + body %zu)\n",
                blob_size,
                sizeof(sealed_blob_header_t) + header->total_size,
                sizeof(sealed_blob_header_t),
                header->total_size);
        }
        else
            printf(
                "Sealed blob with invalid format (size %zu <= %zu)\n",
                blob_size,
                sizeof(sealed_blob_header_t));
    }

    output->data = blob;
    output->size = blob_size;

    result = OE_OK;

done:
    return result;
}

oe_result_t enc_unseal(
    uint8_t* data,
    size_t size,
    output_t* output,
    bool verbose)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* blob = NULL;
    size_t blob_size = 0;

    if (!data || !size || !output)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (verbose)
    {
        sgx_key_request_t key_request = {0};

        _dump_enclave_identities();

        if (_get_default_key_request(&key_request) == OE_OK)
        {
            printf("Default SGX Key Request (current platform):\n");

            _dump_sgx_key_request(&key_request);
        }

        if (size > sizeof(sealed_blob_header_t))
        {
            sealed_blob_header_t* header = (sealed_blob_header_t*)data;

            printf("Sealed blob header:\n");

            _dump_sealed_blob_header(header);

            printf(
                "input_size: %zu, expected: %zu (header %zu + body %zu)\n",
                size,
                sizeof(sealed_blob_header_t) + header->total_size,
                sizeof(sealed_blob_header_t),
                header->total_size);
        }
        else
            printf(
                "Sealed blob with invalid format (size %zu <= %zu)\n",
                size,
                sizeof(sealed_blob_header_t));
    }

    OE_CHECK(oe_unseal(data, size, NULL, 0, &blob, &blob_size));

    output->data = blob;
    output->size = blob_size;

    result = OE_OK;

done:
    return result;
}

OE_SET_ENCLAVE_SGX2(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    ({0}), /* ExtendedProductID */
    ({0}), /* FamilyID */
    true,  /* Debug */
    true,  /* CapturePFGPExceptions */
    false, /* RequireKSS */
    false, /* CreateZeroBaseEnclave */
    0,     /* StartAddress */
    1024,  /* NumHeapPages */
    1024,  /* NumStackPages */
    1);    /* NumTCS */
