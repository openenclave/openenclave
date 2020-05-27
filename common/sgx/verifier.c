// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>

#include "../common.h"
#include "endorsements.h"
#include "quote.h"
#if defined(OE_LINK_SGX_DCAP_QL) && !defined(OE_BUILD_ENCLAVE)
#include "../../host/sgx/sgxquoteprovider.h"
#endif

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/thread.h>
#include "../../enclave/core/sgx/report.h"
#include "../enclave/sgx/report.h"
#else
#include "../../host/hostthread.h"
#include "../../host/sgx/quote.h"
typedef oe_mutex oe_mutex_t;
#define OE_MUTEX_INITIALIZER OE_H_MUTEX_INITIALIZER
#endif

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

#if defined(OE_BUILD_ENCLAVE) || !defined(OE_LINK_SGX_DCAP_QL)
    return OE_OK;
#else
    return oe_initialize_quote_provider();
#endif
}

static oe_result_t _on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    return OE_OK;
}

static void _free_claim(oe_claim_t* claim)
{
    oe_free(claim->name);
    oe_free(claim->value);
}

static oe_result_t _free_claims(
    oe_verifier_t* context,
    oe_claim_t* claims,
    size_t claims_length)
{
    OE_UNUSED(context);
    if (!claims)
        return OE_OK;

    for (size_t i = 0; i < claims_length; i++)
        _free_claim(&claims[i]);
    oe_free(claims);
    return OE_OK;
}

static oe_result_t _get_input_time(
    const oe_policy_t* policies,
    size_t policies_size,
    oe_datetime_t** time)
{
    if (!policies)
    {
        *time = NULL;
        return OE_OK;
    }

    for (size_t i = 0; i < policies_size; i++)
    {
        if (policies[i].type == OE_POLICY_ENDORSEMENTS_TIME)
        {
            if (policies[i].policy_size != sizeof(**time))
                return OE_INVALID_PARAMETER;

            *time = (oe_datetime_t*)policies[i].policy;
            return OE_OK;
        }
    }

    // Time not found, which is fine since it's an optional parameter.
    *time = NULL;
    return OE_OK;
}

static oe_result_t _verify_local_report(
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size)
{
    // Do a normal report verification on the enclave side.
    // Local report verification is unsupported for host side.
#ifdef OE_BUILD_ENCLAVE
    return oe_verify_report_internal(
        evidence_buffer, evidence_buffer_size, NULL);
#else
    OE_UNUSED(evidence_buffer);
    OE_UNUSED(evidence_buffer_size);
    return OE_UNSUPPORTED;
#endif
}

static oe_result_t _verify_claims_hash(
    const uint8_t* report,
    oe_report_type_t report_type,
    const uint8_t* claims,
    size_t claims_size)
{
    oe_result_t result = OE_UNEXPECTED;
    int hash_cmp = 0;
    OE_SHA256 hash;
    oe_sha256_context_t hash_ctx = {0};

    OE_CHECK(oe_sha256_init(&hash_ctx));
    OE_CHECK(oe_sha256_update(&hash_ctx, claims, claims_size));
    OE_CHECK(oe_sha256_final(&hash_ctx, &hash));

    if (report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        hash_cmp = memcmp(
            &((sgx_quote_t*)report)->report_body.report_data,
            &hash,
            OE_SHA256_SIZE);
    }
    else if (report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        hash_cmp = memcmp(
            &((sgx_report_t*)report)->body.report_data, &hash, OE_SHA256_SIZE);
    }
    else
        OE_RAISE(OE_INVALID_PARAMETER);

    result = (hash_cmp == 0) ? OE_OK : OE_QUOTE_HASH_MISMATCH;
done:
    return result;
}

static oe_result_t _add_claim(
    oe_claim_t* claim,
    const void* name,
    size_t name_size,
    const void* value,
    size_t value_size)
{
    if (*((uint8_t*)name + name_size - 1) != '\0')
        return OE_CONSTRAINT_FAILED;

    claim->name = (char*)oe_malloc(name_size);
    if (claim->name == NULL)
        return OE_OUT_OF_MEMORY;
    memcpy(claim->name, name, name_size);

    claim->value = (uint8_t*)oe_malloc(value_size);
    if (claim->value == NULL)
    {
        oe_free(claim->name);
        claim->name = NULL;
        return OE_OUT_OF_MEMORY;
    }
    memcpy(claim->value, value, value_size);
    claim->value_size = value_size;

    return OE_OK;
}

static oe_result_t _fill_with_known_claims(
    const oe_uuid_t* format_id,
    const uint8_t* report,
    size_t report_size,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_claim_t* claims,
    size_t claims_length,
    size_t* claims_added)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t parsed_report = {0};
    oe_identity_t* id = &parsed_report.identity;
    size_t claims_index = 0;
    oe_report_header_t* header = (oe_report_header_t*)report;
    oe_datetime_t valid_from = {0};
    oe_datetime_t valid_until = {0};

    if (claims_length < OE_REQUIRED_CLAIMS_COUNT)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_parse_report(report, report_size, &parsed_report));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE &&
        claims_length < OE_REQUIRED_CLAIMS_COUNT + OE_OPTIONAL_CLAIMS_COUNT)
        OE_RAISE(OE_INVALID_PARAMETER);

    // ID version.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ID_VERSION,
        sizeof(OE_CLAIM_ID_VERSION),
        &id->id_version,
        sizeof(id->id_version)));

    // Security version.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SECURITY_VERSION,
        sizeof(OE_CLAIM_SECURITY_VERSION),
        &id->security_version,
        sizeof(id->security_version)));

    // Attributes.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ATTRIBUTES,
        sizeof(OE_CLAIM_ATTRIBUTES),
        &id->attributes,
        sizeof(id->attributes)));

    // Unique ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_UNIQUE_ID,
        sizeof(OE_CLAIM_UNIQUE_ID),
        &id->unique_id,
        sizeof(id->unique_id)));

    // Signer ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SIGNER_ID,
        sizeof(OE_CLAIM_SIGNER_ID),
        &id->signer_id,
        sizeof(id->signer_id)));

    // Product ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_PRODUCT_ID,
        sizeof(OE_CLAIM_PRODUCT_ID),
        &id->product_id,
        sizeof(id->product_id)));

    // Plugin UUID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_FORMAT_UUID,
        sizeof(OE_CLAIM_FORMAT_UUID),
        format_id,
        sizeof(*format_id)));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        // Get quote validity periods to get validity from and until claims.
        OE_CHECK(oe_get_sgx_quote_validity(
            header->report,
            header->report_size,
            sgx_endorsements,
            &valid_from,
            &valid_until));

        // Validity from.
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_VALIDITY_FROM,
            sizeof(OE_CLAIM_VALIDITY_FROM),
            &valid_from,
            sizeof(valid_from)));

        // Validity to.
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_VALIDITY_UNTIL,
            sizeof(OE_CLAIM_VALIDITY_UNTIL),
            &valid_until,
            sizeof(valid_until)));
    }

    *claims_added = claims_index;
    result = OE_OK;

done:
    if (result != OE_OK)
    {
        for (size_t i = 0; i < claims_index; i++)
            _free_claim(&claims[i]);
    }
    return result;
}

static oe_result_t _fill_with_custom_claims(
    const uint8_t* claims_buf,
    size_t claims_buf_size,
    oe_claim_t* claims,
    size_t claims_length)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sgx_plugin_claims_header_t* header =
        (oe_sgx_plugin_claims_header_t*)claims_buf;
    size_t claims_index = 0;

    if (claims_length < header->num_claims)
        OE_RAISE(OE_INVALID_PARAMETER);

    claims_buf += sizeof(*header);
    claims_buf_size -= sizeof(*header);
    for (uint64_t i = 0; i < header->num_claims; i++)
    {
        oe_sgx_plugin_claims_entry_t* entry =
            (oe_sgx_plugin_claims_entry_t*)claims_buf;
        uint64_t size;

        // Sanity check sizes.
        if (claims_buf_size < sizeof(*entry))
            OE_RAISE(OE_CONSTRAINT_FAILED);

        OE_CHECK(oe_safe_add_u64(sizeof(*entry), entry->name_size, &size));
        OE_CHECK(oe_safe_add_u64(size, entry->value_size, &size));

        if (claims_buf_size < size)
            OE_RAISE(OE_CONSTRAINT_FAILED);

        // Finally, add the claim.
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            entry->name,
            entry->name_size,
            entry->name + entry->name_size,
            entry->value_size));

        // Go to next entry.
        claims_buf += size;
        claims_buf_size -= size;
    }

    result = OE_OK;

done:
    if (result != OE_OK)
    {
        for (size_t i = 0; i < claims_index; i++)
            _free_claim(&claims[i]);
    }
    return result;
}

oe_result_t oe_sgx_extract_claims(
    const oe_uuid_t* format_id,
    const uint8_t* evidence,
    size_t evidence_size,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_claim_t** claims_out,
    size_t* claims_length_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* header = (oe_report_header_t*)evidence;
    oe_sgx_plugin_claims_header_t* claims_header = NULL;
    size_t report_size = sizeof(*header) + header->report_size;
    oe_claim_t* claims = NULL;
    uint64_t claims_length = 0;
    uint64_t claims_size = 0;
    size_t claims_added = 0;

    // Check if the buffer is the proper size.
    if (evidence_size - report_size < sizeof(*claims_header))
        OE_RAISE(OE_INVALID_PARAMETER);

    // verify the integrity of the serialized claims with hash stored in
    // report_data.
    OE_CHECK(_verify_claims_hash(
        header->report,
        header->report_type,
        evidence + report_size,
        evidence_size - report_size));

    claims_header = (oe_sgx_plugin_claims_header_t*)(evidence + report_size);

    // Get the number of claims we need and allocate the claims.
    OE_CHECK(oe_safe_add_u64(
        OE_REQUIRED_CLAIMS_COUNT, claims_header->num_claims, &claims_length));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        OE_CHECK(oe_safe_add_u64(
            claims_length, OE_OPTIONAL_CLAIMS_COUNT, &claims_length));
    }

    OE_CHECK(oe_safe_mul_u64(claims_length, sizeof(oe_claim_t), &claims_size));

    claims = (oe_claim_t*)oe_malloc(claims_size);
    if (claims == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Fill the list with the known claims.
    OE_CHECK(_fill_with_known_claims(
        format_id,
        evidence,
        report_size,
        sgx_endorsements,
        claims,
        claims_length,
        &claims_added));

    // Fill with the custom claims.
    OE_CHECK(_fill_with_custom_claims(
        evidence + report_size,
        evidence_size - report_size,
        claims + claims_added,
        claims_length - claims_added));

    *claims_out = claims;
    *claims_length_out = claims_length;
    claims = NULL;
    result = OE_OK;

done:
    if (claims)
        _free_claims(NULL, claims, claims_length);
    return result;
}

static oe_result_t _verify_evidence(
    oe_verifier_t* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* header = (oe_report_header_t*)evidence_buffer;
    oe_datetime_t* time = NULL;
    uint8_t* local_endorsements_buffer = NULL;
    size_t local_endorsements_buffer_size = 0;
    oe_sgx_endorsements_t sgx_endorsements;
    OE_UNUSED(context);

    if (!evidence_buffer || !claims || !claims_length ||
        evidence_buffer_size < sizeof(*header) ||
        evidence_buffer_size - sizeof(*header) < header->report_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Check the datetime policy if it exists.
    OE_CHECK(_get_input_time(policies, policies_size, &time));

    // Verify the report. Send the report size to just the oe report,
    // not including the custom claims section.
    if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        OE_CHECK(_verify_local_report(
            evidence_buffer, header->report_size + sizeof(oe_report_header_t)));
    }
    else
    {
        // Get the endorsements if none were provided.
        if (endorsements_buffer == NULL)
        {
            OE_CHECK(oe_get_sgx_endorsements(
                header->report,
                header->report_size,
                &local_endorsements_buffer,
                &local_endorsements_buffer_size));
            endorsements_buffer = local_endorsements_buffer;
            endorsements_buffer_size = local_endorsements_buffer_size;
        }

        // Parse into SGX endorsements.
        OE_CHECK(oe_parse_sgx_endorsements(
            (oe_endorsements_t*)endorsements_buffer,
            endorsements_buffer_size,
            &sgx_endorsements));

        // Verify the quote now.
        OE_CHECK(oe_verify_quote_with_sgx_endorsements(
            header->report, header->report_size, &sgx_endorsements, time));
    }

    // Last step is to return the required and custom claims.
    OE_CHECK(oe_sgx_extract_claims(
        &context->base.format_id,
        evidence_buffer,
        evidence_buffer_size,
        &sgx_endorsements,
        claims,
        claims_length));

    result = OE_OK;

done:
    if (local_endorsements_buffer)
        oe_free_sgx_endorsements(local_endorsements_buffer);

    return result;
}

// Gets the optional format settings for the given verifier plugin context.
// For SGX local attestation, this would be the sgx_target_info_t struct.
static oe_result_t _get_format_settings(
    oe_verifier_t* context,
    uint8_t** settings,
    size_t* settings_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* report = NULL;

    if (!context || !settings || !settings_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!memcmp(&context->base.format_id, &_local_uuid, sizeof(oe_uuid_t)))
    {
#ifdef OE_BUILD_ENCLAVE
        // Enclave-side, SGX local attestation is supported
        uint8_t* tmp_target = NULL;
        size_t tmp_target_size = 0;

        report = (oe_report_header_t*)oe_malloc(
            sizeof(oe_report_header_t) + sizeof(sgx_report_t));
        if (!report)
            OE_RAISE(OE_OUT_OF_MEMORY);

        OE_CHECK(sgx_create_report(
            NULL, 0, NULL, 0, (sgx_report_t*)&report->report));

        report->version = OE_REPORT_HEADER_VERSION;
        report->report_type = OE_REPORT_TYPE_SGX_LOCAL;
        report->report_size = sizeof(sgx_report_t);

        OE_CHECK(oe_get_target_info_v2(
            (const uint8_t*)report,
            sizeof(oe_report_header_t) + sizeof(sgx_report_t),
            (void**)&tmp_target,
            &tmp_target_size));

        *settings = tmp_target;
        *settings_size = tmp_target_size;
        tmp_target = NULL;
        result = OE_OK;
#else
        // Host-side, SGX local attestation is not supported
        OE_RAISE(OE_UNSUPPORTED);
#endif
    }
    else if (!memcmp(&context->base.format_id, &_ecdsa_uuid, sizeof(oe_uuid_t)))
    {
        *settings = NULL;
        *settings_size = 0;
        result = OE_OK;
    }
    else
    {
        OE_RAISE(OE_UNSUPPORTED);
    }

done:
    if (report)
        oe_free(report);
    return result;
}

static oe_result_t _verify_report(
    oe_verifier_t* context,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !report || report_size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Enclave-side, verifies ECDSA and local report
    // Host-side, verifies only ECDSA report
    if (
#ifdef OE_BUILD_ENCLAVE
        !memcmp(&context->base.format_id, &_local_uuid, sizeof(oe_uuid_t)) ||
#endif
        !memcmp(&context->base.format_id, &_ecdsa_uuid, sizeof(oe_uuid_t)))
    {
#ifdef OE_BUILD_ENCLAVE
        OE_CHECK(oe_verify_report_internal(report, report_size, parsed_report));
#else
        OE_CHECK(oe_verify_report_internal(
            NULL, report, report_size, parsed_report));
#endif
        result = OE_OK;
    }
    else
        OE_RAISE(OE_UNSUPPORTED);

done:
    return result;
}

static oe_result_t _get_verifier_plugins(
    oe_verifier_t** verifiers,
    size_t* verifiers_length)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t uuid_count = 0;

    if (!verifiers || !verifiers_length)
        OE_RAISE(OE_INVALID_PARAMETER);

#ifdef OE_BUILD_ENCLAVE
    uuid_count = 2; // In enclave, only support local and ECDSA formats
#else
    uuid_count = 1; // In host, only support ECDSA format
#endif

    *verifiers = (oe_verifier_t*)oe_malloc(sizeof(oe_verifier_t) * uuid_count);
    if (*verifiers == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    for (size_t i = 0; i < uuid_count; i++)
    {
        oe_verifier_t* plugin = *verifiers + i;
        memcpy(
            &plugin->base.format_id,
#ifdef OE_BUILD_ENCLAVE
            (!i ? &_local_uuid : &_ecdsa_uuid),
#else
            &_ecdsa_uuid,
#endif
            sizeof(oe_uuid_t));
        plugin->base.on_register = &_on_register;
        plugin->base.on_unregister = &_on_unregister;
        plugin->get_format_settings = &_get_format_settings;
        plugin->verify_evidence = &_verify_evidence;
        plugin->verify_report = &_verify_report;
        plugin->free_claims = &_free_claims;
    }
    *verifiers_length = uuid_count;
    result = OE_OK;

done:
    return result;
}

static oe_verifier_t* verifiers = NULL;
static size_t verifiers_length = 0;
static oe_mutex_t init_mutex = OE_MUTEX_INITIALIZER;

oe_result_t oe_verifier_initialize(void)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_TEST(oe_mutex_lock(&init_mutex) == 0);

    // Do nothing if verifier plugins are already initialized
    if (verifiers)
    {
        OE_TRACE_INFO(
            "verifiers is not NULL, verifiers_length=%d", verifiers_length);
        result = OE_OK;
        goto done;
    }

    OE_CHECK(_get_verifier_plugins(&verifiers, &verifiers_length));

    OE_TRACE_INFO("got verifiers_length=%d plugins", verifiers_length);

    for (size_t i = 0; i < verifiers_length; i++)
    {
        result = oe_register_verifier_plugin(verifiers + i, NULL, 0);
        OE_CHECK(result);
    }
    result = OE_OK;

done:
    oe_mutex_unlock(&init_mutex);
    return result;
}

// Registration of plugins does not allocate any resources to them.
oe_result_t oe_verifier_shutdown(void)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_TEST(oe_mutex_lock(&init_mutex) == 0);

    // Either verifier plugins have not been initialized,
    // or there is no supported plugin
    if (!verifiers)
    {
        OE_TRACE_INFO("verifiers is NULL");
        result = OE_OK;
        goto done;
    }

    OE_TRACE_INFO("free verifiers_length=%d plugins", verifiers_length);

    for (size_t i = 0; i < verifiers_length; i++)
    {
        result = oe_unregister_verifier_plugin(verifiers + i);
        if (result != OE_OK)
            OE_TRACE_ERROR(
                "oe_unregister_verifier_plugin() #%lu failed with %s",
                i,
                oe_result_str(result));
    }

    oe_free(verifiers);
    verifiers = NULL;
    verifiers_length = 0;
    result = OE_OK;

done:
    oe_mutex_unlock(&init_mutex);
    return result;
}
