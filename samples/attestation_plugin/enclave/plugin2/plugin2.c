// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This plugin is an example for supporting token validation

// Sample JWT token data
//
// HEADER:ALGORITHM & TOKEN TYPE
// {
//   "alg": "HS256",
//   "typ": "JWT"
// }
// PAYLOAD:DATA
// {
//   "sub": "1234567890",
//   "name": "John Doe",
//   "iat": 1516239022
// }
// VERIFY SIGNATURE
// HMACSHA256(
//   base64UrlEncode(header) + "." +
//   base64UrlEncode(payload),
// your-256-bit-secret
// ) secret base64 encoded

static unsigned char g_custom_evidence[] =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
static size_t g_custom_evidence_size = sizeof(g_custom_evidence);

static int my_get_custom_evidence_data(
    oe_attestation_plugin_context_t* plugin_context,
    uint8_t** custom_evidence,
    size_t* custom_evidence_size)
{
    int ret = 1;
    uint8_t* buffer = NULL;

    fprintf(stdout, "\nmy_get_custom_evidence_data 2\n");

    // create custom data here
    *custom_evidence_size = g_custom_evidence_size;
    buffer = (uint8_t*)malloc(g_custom_evidence_size);
    if (buffer == NULL)
    {
        fprintf(stdout, "failed to allocate memory for custom evidence data");
        goto done;
    }

    // fill custom evidence with token info
    memcpy(
        (void*)buffer, (const void*)g_custom_evidence, g_custom_evidence_size);

    *custom_evidence = buffer;
    ret = 0;
done:
    return ret;
}

static int my_verify_custom_evidence(
    oe_attestation_plugin_context_t* plugin_context,
    const uint8_t* custom_evidence,
    size_t custom_evidence_size,
    oe_claim_element_t** claims,
    size_t* claim_count)
{
    int ret = 1;

    (void)plugin_context;
    (void)claims;
    (void)claim_count;

    fprintf(stdout, "my_verify_custom_evidence 2\n");

    if (custom_evidence_size != g_custom_evidence_size)
    {
        fprintf(
            stdout,
            "unexpected custom_evidence_size(%zu)!\n",
            custom_evidence_size);
        goto done;
    }

    // verifiy passed in data is same as original contents
    for (int i = 0; i < custom_evidence_size; i++)
    {
        if (custom_evidence[i] != g_custom_evidence[i])
        {
            goto done;
        }
    }

    // TODO:
    // verify the Sample JWT token here

    ret = 0;
done:
    return ret;
}

static oe_attestation_plugin_callbacks_t attestation_callbacks = {
    .get_custom_evidence = my_get_custom_evidence_data,
    .verify_custom_evidence = my_verify_custom_evidence,
    .verify_full_evidence = NULL,
};

// // {F36B727E-A818-47B6-A6CD-5853B84593A2}
// static const GUID <<name>> =
// { 0xf36b727e, 0xa818, 0x47b6, { 0xa6, 0xcd, 0x58, 0x53, 0xb8, 0x45, 0x93,
// 0xa2 } };
oe_attestation_plugin_context_t my_plugin_context2 = {
    .tee_evidence_type = OE_TEE_TYPE_CUSTOM,
    .evidence_format_uuid = UUID_INIT(
        0xF36B727E,
        0xA818,
        0x47B6,
        0xA6,
        0xCD,
        0x58,
        0x53,
        0xb8,
        0x45,
        0x93,
        0xA2),
    .callbacks = &attestation_callbacks,
};
