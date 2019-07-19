// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This plugin is an example for supporting custom evidence data

static size_t g_custom_evidence_size = 1024;

static int my_get_custom_evidence_data(
    oe_quote_customization_plugin_context_t* plugin_context,
    uint8_t** custom_evidence,
    size_t* custom_evidence_size)
{
    int ret = 1;
    uint8_t* buffer = NULL;

    fprintf(stdout, "my_get_custom_evidence_data 1\n");

    // create custom data here
    *custom_evidence_size = g_custom_evidence_size;
    buffer = (uint8_t*)malloc(g_custom_evidence_size);
    if (buffer == NULL)
    {
        fprintf(stdout, "failed to allocate memory for custom evidence data");
        goto done;
    }

    // fill in some test data
    for (int i = 0; i < g_custom_evidence_size; i++)
    {
        buffer[i] = i % 256;
    }
    *custom_evidence = buffer;
    ret = 0;
done:
    return ret;
}

static int my_verify_custom_evidence(
    oe_quote_customization_plugin_context_t* plugin_context,
    const uint8_t* custom_evidence,
    size_t custom_evidence_size,
    oe_claim_element_t** claims,
    size_t* claim_count)
{
    int ret = 1;
    oe_claim_element_t* my_claims = NULL;
    oe_claim_element_t* new_claim = NULL;
    (void)plugin_context;
    fprintf(stdout, "my_verify_custom_evidence 1\n");

    (void)claims;
    (void)claim_count;

    for (int i = 0; i < custom_evidence_size; i++)
    {
        if (custom_evidence[i] != (i % 256))
        {
            fprintf(stdout, "my_verify_custom_evidence failed 1\n");
            goto done;
        }
    }

    // create new claim after processing above custom data
    new_claim = (oe_claim_element_t*)malloc(sizeof(oe_claim_element_t));
    if (new_claim == NULL)
    {
        goto done;
    }
    char* location_value = "East US";
    new_claim->name = "geolocation";
    new_claim->len = strlen(location_value) + 1;
    new_claim->value = (uint8_t*)malloc(new_claim->len);
    if (new_claim->value == NULL)
    {
        goto done;
    }
    memcpy((void*)new_claim->value, location_value, new_claim->len);

    // add new claim into the existing list
    my_claims = (oe_claim_element_t*)malloc(
        sizeof(oe_claim_element_t) * (*claim_count + 1));
    if (my_claims == NULL)
    {
        goto done;
    }
    // copy existing claims to a new array
    for (int i = 0; i < *claim_count; i++)
    {
        my_claims[i] = (*claims)[i];
    }
    // add one evidence here
    my_claims[*claim_count] = *new_claim;
    free(*claims);

    *claims = my_claims;
    *claim_count = *claim_count + 1;
    ret = 0;
done:

    return ret;
}

static oe_quote_customization_plugin_callbacks_t attestation_callbacks = {
    .get_custom_evidence = my_get_custom_evidence_data,
    .verify_custom_evidence = my_verify_custom_evidence,
    .verify_full_evidence = NULL,
};

// // {6EBB65E5-F657-48B1-94DF-0EC0B671DA26}
// static const GUID <<name>> =
// { 0x6EBB65E5, 0xF657, 0x48B1, { 0x94, 0xdf, 0x0e, 0xc0, 0xb6, 0x71,0xda,
// 0x26 } };
oe_quote_customization_plugin_context_t my_plugin_context1 = {
    .tee_evidence_type = OE_TEE_TYPE_SGX_REMOTE,
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
    .callbacks = &attestation_callbacks,
};
