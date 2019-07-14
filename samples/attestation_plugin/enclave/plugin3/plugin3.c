// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

// clang-format off
#include <mbedtls/sha256.h>
#include <mbedtls/platform.h>
// clang-format on

#include <stdio.h>
#include <stdlib.h>

// This plugin is an example for supporting full evidence validation --  in
// progress

#define SHA256_SIZE 32
static size_t g_custom_evidence_size = 1024;
uint8_t g_attestation_collateral[1024];

// Compute the sha256 hash of given data.
static int sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto done;

    ret = mbedtls_sha256_update_ret(&ctx, data, data_size);
    if (ret)
        goto done;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto done;

done:
    mbedtls_sha256_free(&ctx);
    return ret;
}

// static int my_get_custom_evidence_size(
//     oe_attestation_plugin_context_t* plugin_context,
//     size_t* custom_evidence_size)
// {
//     int ret = 1;

//     fprintf(stdout, "my_get_custom_evidence_size 3\n");

//     // 1. oe_get_attestation_collaterals();

//     // 2. serialize attestation collaterals and turn it into custom_evidence

//     // 2.1 cache collaterals in preparatin for get_custom_evidence call.

//     // 3. calculate its size before setting it to custom_evidence_size
//     if (custom_evidence_size == NULL)
//         goto done;

//     // g_custom_evidence_size = sizeof(attestation_collaterals);

//     *custom_evidence_size = g_custom_evidence_size;

//     ret = 0;

// done:
//     return ret;
// }

static int my_get_custom_evidence_data(
    oe_attestation_plugin_context_t* plugin_context,
    uint8_t** custom_evidence,
    size_t* custom_evidence_size)
{
    int ret = 1;
    uint8_t* buffer = NULL;

    fprintf(stdout, "my_get_custom_evidence_data 3\n");

    buffer = (uint8_t*)malloc(g_custom_evidence_size);
    if (buffer == NULL)
    {
        fprintf(stdout, "failed to allocate memory for custom evidence data");
        goto done;
    }

    // TODO: copy over the cached collaterals to the custom_evidence buffer
    for (int i = 0; i < g_custom_evidence_size; i++)
    {
        buffer[i] = i % 256;
    }

    *custom_evidence = buffer;
    ret = 0;
done:
    return ret;
}

static int my_verify_full_evidence(
    oe_attestation_plugin_context_t* plugin_context,
    const uint8_t* full_evidence_buffer,
    size_t full_evidence_buffer_size,
    oe_claim_element_t** claims,
    size_t* claim_count)
{
    int ret = 1;
    oe_result_t result = OE_FAILURE;
    struct attestation_plugin_t* plugin = NULL;
    uint64_t custom_evidence_size = 0;
    uint8_t* custom_evidence = NULL;
    uint8_t sha256_data[SHA256_SIZE];
    oe_evidence_header_t* header = (oe_evidence_header_t*)full_evidence_buffer;

    (void)plugin_context;
    (void)claims;
    (void)claim_count;

    fprintf(stdout, "my_verify_full_evidence 3\n");

    // extract custom data
    custom_evidence = header->tee_evidence + header->tee_evidence_size;
    custom_evidence_size = header->custom_evidence_size;

    //
    // validate quote with attestation collaterals
    //
    // result =
    //     oe_verify_report_ex(full_evidence_buffer,
    //                         full_evidence_buffer_size,
    //                         custom_evidence,
    //                         custom_evidence_size,
    //                         parsed_report);
    // if (result != OE_OK)
    // {
    //     fprintf(stdout, "oe_verify_report failed (%s).\n",
    //     oe_result_str(result)); goto done;
    // }

    //
    // verify hash for custom data
    //
    // sha256(custom_evidence, custom_evidence_size, sha256_data);
    // if (memcmp(parsed_report->report_data, (uint8_t*)sha256_data,
    // SHA256_SIZE) !=  0)
    // {
    //     result = OE_VERIFY_FAILED;
    //     fprintf(stdout, "report_data checking failed (%s).\n");
    //     goto done;
    // }
    result = OE_OK;
    ret = 0;
done:
    if (result != OE_OK)
        ret = 1;

    return ret;
}

static oe_attestation_plugin_callbacks_t attestation_callbacks = {
    .get_custom_evidence = my_get_custom_evidence_data,
    .verify_custom_evidence = NULL,
    .verify_full_evidence = my_verify_full_evidence,
};

// // {B9BA3261-CB33-4171-8FB3-D4E1CCA1EA40}
// static const GUID <<name>> =
// { 0xb9ba3261, 0xcb33, 0x4171, { 0x8f, 0xb3, 0xd4, 0xe1, 0xcc, 0xa1, 0xea,
// 0x40 } };
oe_attestation_plugin_context_t my_plugin_context3 = {
    .tee_evidence_type = OE_TEE_TYPE_SGX_REMOTE,
    .evidence_format_uuid = UUID_INIT(
        0xB9BA3261,
        0xCB33,
        0x4171,
        0x8F,
        0xB3,
        0xD4,
        0xE1,
        0xCC,
        0xA1,
        0xEA,
        0x40),
    .callbacks = &attestation_callbacks,
};
