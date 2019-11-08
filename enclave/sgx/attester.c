// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/attestation/plugin.h>
#include <openenclave/attestation/sgx/attester.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>

#include <mbedtls/sha256.h>

#include "../common/sgx/endorsements.h"

static oe_result_t _on_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);
    return OE_OK;
}

static oe_result_t _on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    return OE_OK;
}

static size_t _get_claims_size(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length)
{
    size_t size = sizeof(oe_sgx_plugin_claims_header_t);

    if (!custom_claims)
        return size;

    for (size_t i = 0; i < custom_claims_length; i++)
    {
        size += sizeof(oe_sgx_plugin_claims_entry_t);
        size += oe_strlen(custom_claims[i].name) + 1;
        size += custom_claims[i].value_size;
    }
    return size;
}

static void _set_claims(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t* claims)
{
    // Custom claims structure would be:
    //  - oe_sgx_plugin_claims_header_t
    //  - N claim entries of oe_sgx_plugin_claims_entry_t
    oe_sgx_plugin_claims_header_t* header =
        (oe_sgx_plugin_claims_header_t*)claims;
    header->version = OE_SGX_PLUGIN_CLAIMS_VERSION;
    header->num_claims = custom_claims ? custom_claims_length : 0;
    claims += sizeof(oe_sgx_plugin_claims_header_t);

    if (!custom_claims)
        return;

    for (size_t i = 0; i < custom_claims_length; i++)
    {
        oe_sgx_plugin_claims_entry_t* entry =
            (oe_sgx_plugin_claims_entry_t*)claims;
        entry->name_size = oe_strlen(custom_claims[i].name) + 1;
        entry->value_size = custom_claims[i].value_size;
        memcpy(entry->name, custom_claims[i].name, entry->name_size);
        memcpy(
            entry->name + entry->name_size,
            custom_claims[i].value,
            entry->value_size);
        claims += sizeof(*entry) + entry->name_size + entry->value_size;
    }
}

static oe_result_t _serialize_claims(
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    uint8_t** claims_out,
    size_t* claims_size_out,
    OE_SHA256* hash_out)
{
    uint8_t* claims = NULL;
    size_t claims_size = 0;
    oe_sha256_context_t hash_ctx = {0};
    oe_result_t result = OE_UNEXPECTED;

    // Get claims size.
    claims_size = _get_claims_size(custom_claims, custom_claims_length);

    // Allocate memory and set the claims.
    claims = (uint8_t*)oe_malloc(claims_size);
    if (claims == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);
    _set_claims(custom_claims, custom_claims_length, claims);

    // Produce a hash of the claims.
    OE_CHECK(oe_sha256_init(&hash_ctx));
    OE_CHECK(oe_sha256_update(&hash_ctx, claims, claims_size));
    OE_CHECK(oe_sha256_final(&hash_ctx, hash_out));

    *claims_out = claims;
    *claims_size_out = claims_size;
    claims = NULL;
    result = OE_OK;

done:
    if (claims != NULL)
        oe_free(claims);
    return result;
}

static oe_result_t _get_evidence(
    oe_attester_t* context,
    uint32_t flags,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* claims = NULL;
    size_t claims_size = 0;
    OE_SHA256 hash;
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* evidence = NULL;
    uint8_t* endorsements = NULL;
    size_t endorsements_size = 0;
    OE_UNUSED(context);

    if (!evidence_buffer || !evidence_buffer_size ||
        (endorsements_buffer && !endorsements_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Serialize the claims.
    OE_CHECK_MSG(
        _serialize_claims(
            custom_claims, custom_claims_length, &claims, &claims_size, &hash),
        "SGX Plugin: Failed to serialize claims. %s",
        oe_result_str(result));

    // Get the report with the hash of the claims as the report data.
    OE_CHECK_MSG(
        oe_get_report(
            flags,
            hash.buf,
            sizeof(hash.buf),
            opt_params,
            opt_params_size,
            &report,
            &report_size),
        "SGX Plugin: Failed to get OE report. %s",
        oe_result_str(result));

    // Combine the two to get the evidence.
    // Format is report first then claims.
    evidence = (uint8_t*)oe_malloc(report_size + claims_size);
    if (evidence == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    memcpy(evidence, report, report_size);
    memcpy(evidence + report_size, claims, claims_size);

    // Get the endorsements from the report if needed.
    if (endorsements_buffer && flags == OE_REPORT_FLAGS_REMOTE_ATTESTATION)
    {
        oe_report_header_t* header = (oe_report_header_t*)report;

        OE_CHECK_MSG(
            oe_get_sgx_endorsements(
                header->report,
                header->report_size,
                &endorsements,
                &endorsements_size),
            "SGX Plugin: Failed to get endorsements: %s",
            oe_result_str(result));
    }

    *evidence_buffer = evidence;
    *evidence_buffer_size = report_size + claims_size;
    evidence = NULL;
    if (endorsements_buffer)
    {
        *endorsements_buffer = endorsements;
        *endorsements_buffer_size = endorsements_size;
        endorsements = NULL;
    }
    result = OE_OK;

done:
    oe_free(claims);
    oe_free_report(report);
    if (evidence != NULL)
        oe_free(evidence);
    if (endorsements != NULL)
        oe_free_sgx_endorsements(endorsements);
    return result;
}

static oe_result_t _free_evidence(
    oe_attester_t* context,
    uint8_t* evidence_buffer)
{
    OE_UNUSED(context);
    oe_free(evidence_buffer);
    return OE_OK;
}

static oe_result_t _free_endorsements(
    oe_attester_t* context,
    uint8_t* endorsements_buffer)
{
    OE_UNUSED(context);
    oe_free_sgx_endorsements(endorsements_buffer);
    return OE_OK;
}

static oe_attester_t _attester = {.base =
                                      {
                                          .format_id = OE_SGX_PLUGIN_UUID,
                                          .on_register = &_on_register,
                                          .on_unregister = &_on_unregister,
                                      },
                                  .get_evidence = &_get_evidence,
                                  .free_evidence = &_free_evidence,
                                  .free_endorsements = &_free_endorsements};

oe_attester_t* oe_sgx_plugin_attester()
{
    return &_attester;
}