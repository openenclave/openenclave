// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>

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

// static int init_plugin()
// {
//     fprintf(stdout, "initializing attetation plugin 2\n");
//     return 0;
// }

// static int cleanup_plugin()
// {
//     fprintf(stdout, "cleaning up attetation plugin 2\n");
//     return 0;
// }

static int my_get_custom_evidence_size(size_t* custom_evidence_size)
{
    int ret = 1;

    fprintf(stdout, "my_get_custom_evidence_size 2\n");

    if (custom_evidence_size == NULL)
        goto done;

    *custom_evidence_size = g_custom_evidence_size;
    ret = 0;
done:
    return ret;
}

static int my_get_custom_evidence_data(
    uint8_t* custom_evidence,
    size_t custom_evidence_size)
{
    int ret = 1;

    fprintf(stdout, "my_get_custom_evidence_data 2\n");
    if (custom_evidence_size != g_custom_evidence_size)
    {
        goto done;
    }

    // fill custom evidence with token info
    memcpy((void*)custom_evidence, g_custom_evidence, custom_evidence_size);

    ret = 0;
done:
    return ret;
}

static int my_verify_custom_evidence(
    void* callback_context,
    const uint8_t* custom_evidence,
    size_t custom_evidence_size,
    oe_report_t* parsed_report)
{
    int ret = 1;

    (void)callback_context;
    fprintf(stdout, "my_verify_custom_evidence 2\n");
    if (parsed_report != NULL)
    {
        fprintf(stdout, "parsed_report is not NULL!\n");
        goto done;
    }

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
    // .init_plugin = init_plugin,
    // .cleanup_plugin = cleanup_plugin,
    .get_custom_evidence_size = my_get_custom_evidence_size,
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
    .ops = &attestation_callbacks,
};
