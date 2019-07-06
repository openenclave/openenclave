// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>

// This plugin is an example for supporting custom evidence data

static size_t g_custom_evidence_size = 1024;

static int init_plugin()
{
    fprintf(stdout, "initializing attetation plugin 1\n");
    return 0;
}

static int cleanup_plugin()
{
    fprintf(stdout, "cleaning up attetation plugin 1\n");
    return 0;
}

static int my_get_custom_evidence_size(size_t* custom_evidence_size)
{
    int ret = 1;

    fprintf(stdout, "my_get_custom_evidence_size 1\n");

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
    fprintf(
        stdout,
        "my_get_custom_evidence_data 1, custom_evidence_size=%d\n",
        custom_evidence_size);

    // create custom data here
    // fill in some test data
    for (int i = 0; i < custom_evidence_size; i++)
    {
        custom_evidence[i] = i % 256;
    }

    return 0;
}

static int my_verify_custom_evidence(
    const uint8_t* custom_evidence,
    size_t custom_evidence_size,
    oe_report_t* parsed_report)
{
    int ret = 1;

    fprintf(stdout, "my_verify_custom_evidence 1\n");

    for (int i = 0; i < custom_evidence_size; i++)
    {
        if (custom_evidence[i] != (i % 256))
        {
            fprintf(stdout, "my_verify_custom_evidence failed 1\n");
            goto done;
        }
    }
    ret = 0;
done:

    return ret;
}

static oe_attestation_plugin_callbacks_t attestation_callbacks = {
    .init_plugin = init_plugin,
    .cleanup_plugin = cleanup_plugin,
    .get_custom_evidence_size = my_get_custom_evidence_size,
    .get_custom_evidence = my_get_custom_evidence_data,
    .verify_custom_evidence = my_verify_custom_evidence,
    .verify_full_evidence = NULL,
};

// // {6EBB65E5-F657-48B1-94DF-0EC0B671DA26}
// static const GUID <<name>> =
// { 0x6EBB65E5, 0xF657, 0x48B1, { 0x94, 0xdf, 0x0e, 0xc0, 0xb6, 0x71,0xda,
// 0x26 } };
oe_attestation_plugin_context_t my_plugin_context1 = {
    .report_type = OE_REPORT_TYPE_SGX_REMOTE,
    .evidence_format_uuid = UUID_INIT(
        0x6EBB65E5,
        0xF657,
        0x48B1,
        0x94,
        0xDF,
        0x0E,
        0xC0,
        0xB6,
        0x71,
        0xDA,
        0x26),
    .ops = &attestation_callbacks,
};
