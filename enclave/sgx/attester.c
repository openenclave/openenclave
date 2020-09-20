// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
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
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>

#include <mbedtls/sha256.h>

#include "../common/attest_plugin.h"
#include "../common/sgx/endorsements.h"
#include "../core/sgx/report.h"
#include "platform_t.h"

/**
 * Declare the prototype of the following function to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_get_supported_attester_format_ids_ocall(
    oe_result_t* _retval,
    void* format_ids,
    size_t format_ids_size,
    size_t* format_ids_size_out);

/**
 * Make the following OCALL weak to support the system EDL opt-in.
 * When the user does not opt into (import) the EDL, the linker will pick
 * the following default implementation. If the user opts into the EDL,
 * the implementation (which is strong) in the oeedger8r-generated code will be
 * used.
 */
oe_result_t _oe_get_supported_attester_format_ids_ocall(
    oe_result_t* _retval,
    void* format_ids,
    size_t format_ids_size,
    size_t* format_ids_size_out)
{
    OE_UNUSED(format_ids);
    OE_UNUSED(format_ids_size);
    OE_UNUSED(format_ids_size_out);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(
    _oe_get_supported_attester_format_ids_ocall,
    oe_get_supported_attester_format_ids_ocall);

static const oe_uuid_t _uuid_sgx_local_attestation = {
    OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static const oe_uuid_t _uuid_sgx_ecdsa = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _uuid_epid_linkable = {OE_FORMAT_UUID_SGX_EPID_LINKABLE};
static const oe_uuid_t _uuid_epid_unlinkable = {
    OE_FORMAT_UUID_SGX_EPID_UNLINKABLE};

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

// Timing note:
// Roughly 0.002 seconds without endorsements.
// Roughtly 0.5 seconds with endorsements.
static oe_result_t _get_evidence(
    oe_attester_t* context,
    const void* custom_claims_buffer,
    size_t custom_claims_buffer_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t flags = 0;
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* tmp_buffer = NULL;
    size_t tmp_buffer_size = 0;
    uint8_t* endorsements = NULL;
    size_t endorsements_size = 0;
    sgx_evidence_format_type_t format_type = SGX_FORMAT_TYPE_UNKNOWN;
    const oe_uuid_t* format_id = NULL;
    // for ECDSA report / quote, oe_get_report_v2_internal() takes
    // the original &_uuid_sgx_ecdsa. quote_format_id holds the format ID
    // for this function.
    const oe_uuid_t* quote_format_id = NULL;
    bool is_epid_quote = false;

    if (!context || !evidence_buffer || !evidence_buffer_size ||
        (endorsements_buffer && !endorsements_buffer_size) ||
        (!endorsements_buffer && endorsements_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    format_id = &context->base.format_id;
    quote_format_id = format_id;

    // Set flags based on format id, ignore and overwrite the input value
    if (!memcmp(format_id, &_uuid_sgx_local_attestation, sizeof(oe_uuid_t)))
    {
        flags = 0;
        format_type = SGX_FORMAT_TYPE_LOCAL;
    }
    else
    {
        flags = OE_REPORT_FLAGS_REMOTE_ATTESTATION;

        if (!memcmp(format_id, &_uuid_sgx_ecdsa, sizeof(oe_uuid_t)))
            format_type = SGX_FORMAT_TYPE_REMOTE;
        else if (
            !memcmp(format_id, &_uuid_epid_linkable, sizeof(oe_uuid_t)) ||
            !memcmp(format_id, &_uuid_epid_unlinkable, sizeof(oe_uuid_t)))
        {
            format_type = SGX_FORMAT_TYPE_RAW_QUOTE;
            is_epid_quote = true;
        }
        else
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    if (format_type == SGX_FORMAT_TYPE_LOCAL ||
        format_type == SGX_FORMAT_TYPE_REMOTE)
    { // Evidence of these types has its custom claims hashed.
        oe_report_header_t* header = NULL;
        OE_SHA256 hash;

        // Hash the custom_claims_buffer.
        OE_CHECK_MSG(
            oe_sgx_hash_custom_claims_buffer(
                custom_claims_buffer, custom_claims_buffer_size, &hash),
            "SGX Plugin: Failed to hash custom_claims_buffer. %s",
            oe_result_str(result));

        // Get the report with the hash of the custom_claims_buffer as the
        // report data.
        OE_CHECK_MSG(
            oe_get_report_v2_internal(
                flags,
                quote_format_id,
                hash.buf,
                sizeof(hash.buf),
                opt_params,
                opt_params_size,
                &report,
                &report_size),
            "SGX Plugin: Failed to get OE report. %s",
            oe_result_str(result));

        // Combine the report body and custom_claims_buffer to get the evidence.
        // Drop the legacy report header
        header = (oe_report_header_t*)report;
        tmp_buffer_size = header->report_size + custom_claims_buffer_size;
        tmp_buffer = (uint8_t*)oe_malloc(tmp_buffer_size);
        if (tmp_buffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        // Copy SGX report body to evidence
        memcpy(tmp_buffer, header->report, header->report_size);
        // Copy custom claims to evidence
        memcpy(
            tmp_buffer + header->report_size,
            custom_claims_buffer,
            custom_claims_buffer_size);

        // Get the endorsements from the report if needed.
        if (endorsements_buffer && flags == OE_REPORT_FLAGS_REMOTE_ATTESTATION)
        {
            OE_CHECK_MSG(
                oe_get_sgx_endorsements(
                    header->report,
                    header->report_size,
                    &endorsements,
                    &endorsements_size),
                "SGX Plugin: Failed to get endorsements: %s",
                oe_result_str(result));
        }
    }
    else if (format_type == SGX_FORMAT_TYPE_RAW_QUOTE)
    {
        oe_report_header_t* header = NULL;

        // Get the report with the custom_claims_buffer as the report data.
        OE_CHECK_MSG(
            oe_get_report_v2_internal(
                flags,
                quote_format_id,
                custom_claims_buffer,
                custom_claims_buffer_size,
                opt_params,
                opt_params_size,
                &report,
                &report_size),
            "SGX Plugin: Failed to get OE report. %s",
            oe_result_str(result));

        // Get the endorsements from the report if needed.
        // No support of endorsements for EPID quotes
        if (endorsements_buffer && !is_epid_quote)
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

        // Discard / overwrite oe_report_header_t structure
        header = (oe_report_header_t*)report;
        tmp_buffer = report;
        tmp_buffer_size = header->report_size;
        memmove(tmp_buffer, header->report, tmp_buffer_size);
        report = NULL;
    }
    else
        OE_RAISE(OE_UNEXPECTED);

    *evidence_buffer = tmp_buffer;
    *evidence_buffer_size = tmp_buffer_size;
    tmp_buffer = NULL;

    if (endorsements_buffer)
    {
        *endorsements_buffer = endorsements;
        *endorsements_buffer_size = endorsements_size;
        endorsements = NULL;
    }
    result = OE_OK;

done:
    if (report)
        oe_free_report(report);
    if (tmp_buffer)
        oe_free(tmp_buffer);
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
    if ((!flags && !memcmp(
                       &context->base.format_id,
                       &_uuid_sgx_local_attestation,
                       sizeof(oe_uuid_t))) ||
        (flags == OE_REPORT_FLAGS_REMOTE_ATTESTATION &&
         !memcmp(
             &context->base.format_id, &_uuid_sgx_ecdsa, sizeof(oe_uuid_t))))
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
            (uint32_t*)&retval, temporary_buffer, temporary_buffer_size, NULL);
        OE_CHECK(result);
        OE_CHECK(retval);
    }

    uuid_list = (oe_uuid_t*)temporary_buffer;
    uuid_count = temporary_buffer_size / sizeof(oe_uuid_t);

    OE_TRACE_INFO("uuid_count=%lu", uuid_count);

    // Add one plugin for SGX local attestation
    *attesters =
        (oe_attester_t*)oe_malloc(sizeof(oe_attester_t) * (1 + uuid_count));
    if (*attesters == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    for (size_t i = 0; i < 1 + uuid_count; i++)
    {
        oe_attester_t* plugin = *attesters + i;
        if (i == 0) // First plugin is for SGX local attestation
            memcpy(
                &plugin->base.format_id,
                &_uuid_sgx_local_attestation,
                sizeof(oe_uuid_t));
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
    *attesters_length = 1 + uuid_count;

    result = OE_OK;

done:
    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING(
            "SGX remote attestation is not enabled. To "
            "enable, please add\n\n"
            "from \"openenclave/edl/sgx/attestation.edl\" import *;\n\n"
            "in the edl file.\n");

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

    if (oe_mutex_lock(&mutex))
        OE_RAISE(OE_UNEXPECTED);

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

    if (oe_mutex_lock(&mutex))
        OE_RAISE(OE_UNEXPECTED);

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
