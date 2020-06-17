// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>

#include <mbedtls/sha256.h>

#include "../common/sgx/endorsements.h"
#include "../core/sgx/report.h"
#include "platform_t.h"

static const oe_uuid_t _local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};

static oe_result_t _on_register(
    oe_attestation_role_t* context,
    const void* configuration_data,
    size_t configuration_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(configuration_data);
    OE_UNUSED(configuration_data_size);
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

oe_result_t oe_sgx_serialize_claims(
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

// Timing note:
// Roughly 0.002 seconds without endorsements.
// Roughtly 0.5 seconds with endorsements.
static oe_result_t _get_evidence(
    oe_attester_t* context,
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
    uint32_t flags = 0;
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

    // Set flags based on format UUID, ignore and overwrite the input value
    if (!memcmp(&context->base.format_id, &_local_uuid, sizeof(oe_uuid_t)))
        flags = 0;
    else
        flags = OE_REPORT_FLAGS_REMOTE_ATTESTATION;

    // Serialize the claims.
    OE_CHECK_MSG(
        oe_sgx_serialize_claims(
            custom_claims, custom_claims_length, &claims, &claims_size, &hash),
        "SGX Plugin: Failed to serialize claims. %s",
        oe_result_str(result));

    // Get the report with the hash of the claims as the report data.
    OE_CHECK_MSG(
        oe_get_report_v2_internal(
            flags,
            &context->base.format_id,
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

static oe_result_t _get_report(
    oe_attester_t* context,
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    // Based on flags, generate local or remote report
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !report_buffer || !report_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Check to ensure the flags matches the plugin UUID
    if ((!flags &&
         !memcmp(&context->base.format_id, &_local_uuid, sizeof(oe_uuid_t))) ||
        (flags == OE_REPORT_FLAGS_REMOTE_ATTESTATION &&
         !memcmp(&context->base.format_id, &_ecdsa_uuid, sizeof(oe_uuid_t))))
    {
        uint8_t* report = NULL;
        size_t report_size = 0;

        OE_CHECK_MSG(
            oe_get_report_v2_internal(
                flags,
                &context->base.format_id,
                report_data,
                report_data_size,
                opt_params,
                opt_params_size,
                &report,
                &report_size),
            "SGX Plugin _get_report(): failed to get %s report. %s",
            (flags ? "ecdsa" : "local"),
            oe_result_str(result));

        *report_buffer = report;
        *report_buffer_size = report_size;
        report = NULL;
        result = OE_OK;
    }
    else // Unsupported flags or plugin
        OE_RAISE(OE_UNSUPPORTED);

done:
    return result;
}

static oe_result_t _get_attester_plugins(
    oe_attester_t** attesters,
    size_t* attesters_length)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_result_t retval = OE_UNEXPECTED;
    size_t temporary_buffer_size = 0;
    uint8_t* temporary_buffer = NULL;
    oe_uuid_t* uuid_list = NULL;
    size_t uuid_count = 0;

    if (!attesters || !attesters_length)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Get the size of the needed buffer
    result = oe_get_supported_attester_format_ids_ocall(
        (uint32_t*)&retval, NULL, 0, &temporary_buffer_size);
    OE_CHECK(result);
    if (retval != OE_OK && retval != OE_BUFFER_TOO_SMALL)
    {
        OE_TRACE_ERROR("unexpected retval=%s", oe_result_str(retval));
        OE_RAISE(retval);
    }
    // It's possible that there is no supported format
    if (temporary_buffer_size >= sizeof(oe_uuid_t))
    {
        // Allocate buffer to held the format IDs
        temporary_buffer = (uint8_t*)oe_malloc(temporary_buffer_size);
        if (temporary_buffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        // Get the format IDs
        result = oe_get_supported_attester_format_ids_ocall(
            (uint32_t*)&retval,
            temporary_buffer,
            temporary_buffer_size,
            &temporary_buffer_size);
        OE_CHECK(result);
        OE_CHECK(retval);
    }

    uuid_list = (oe_uuid_t*)temporary_buffer;
    uuid_count = temporary_buffer_size / sizeof(oe_uuid_t);

    // Add one additional entry: the first one for local attestation
    *attesters =
        (oe_attester_t*)oe_malloc(sizeof(oe_attester_t) * (uuid_count + 1));
    if (*attesters == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    for (size_t i = 0; i < uuid_count + 1; i++)
    {
        oe_attester_t* plugin = *attesters + i;
        if (i == 0)
            memcpy(&plugin->base.format_id, &_local_uuid, sizeof(oe_uuid_t));
        else
            memcpy(
                &plugin->base.format_id,
                uuid_list + (i - 1),
                sizeof(oe_uuid_t));
        plugin->base.on_register = &_on_register;
        plugin->base.on_unregister = &_on_unregister;
        plugin->get_evidence = &_get_evidence;
        plugin->free_evidence = &_free_evidence;
        plugin->free_endorsements = &_free_endorsements;
        plugin->get_report = &_get_report;
    }
    *attesters_length = uuid_count + 1;

    result = OE_OK;

done:
    if (temporary_buffer)
    {
        oe_free(temporary_buffer);
        temporary_buffer = NULL;
    }
    return result;
}

static oe_attester_t* attesters = NULL;
static size_t attesters_length = 0;
static oe_mutex_t mutex = OE_MUTEX_INITIALIZER;

oe_result_t oe_attester_initialize(void)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_TEST(oe_mutex_lock(&mutex) == 0);

    // Do nothing if attester plugins are already initialized
    if (attesters)
    {
        OE_TRACE_INFO(
            "attesters is not NULL, attesters_length=%d", attesters_length);
        result = OE_OK;
        goto done;
    }

    OE_CHECK(_get_attester_plugins(&attesters, &attesters_length));

    OE_TRACE_INFO("got attesters_length=%d plugins", attesters_length);

    for (size_t i = 0; i < attesters_length; i++)
    {
        result = oe_register_attester_plugin(attesters + i, NULL, 0);
        OE_CHECK(result);
    }

    result = OE_OK;

done:
    oe_mutex_unlock(&mutex);
    return result;
}

// There is no per-plugin resource to reclaim,
// since registration of plugins does not allocate any resources for them.
oe_result_t oe_attester_shutdown(void)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_TEST(oe_mutex_lock(&mutex) == 0);

    // Either attester plugins have not been initialized,
    // or there is no supported plugin
    if (!attesters)
    {
        OE_TRACE_INFO("attesters is NULL");
        result = OE_OK;
        goto done;
    }

    OE_TRACE_INFO("free attesters_length=%d plugins", attesters_length);

    for (size_t i = 0; i < attesters_length; i++)
    {
        result = oe_unregister_attester_plugin(attesters + i);
        if (result != OE_OK)
            OE_TRACE_ERROR(
                "oe_unregister_attester_plugin() #%lu failed with %s",
                i,
                oe_result_str(result));
    }

    oe_free(attesters);
    attesters = NULL;
    attesters_length = 0;

    result = OE_OK;

done:
    oe_mutex_unlock(&mutex);
    return result;
}
