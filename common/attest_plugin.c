// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/evidence.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>

#include "attest_plugin.h"
#include "common.h"

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/internal/plugin.h>

#define KEY_BUFF_SIZE 2048

static const char* oid_oe_report = X509_OID_FOR_QUOTE_STRING;
static const char* oid_new_oe_report = X509_OID_FOR_NEW_QUOTE_STRING;
static const char* oid_oe_evidence = X509_OID_FOR_OE_EVIDENCE_STRING;
static const char* oid_new_oe_evidence = X509_OID_FOR_NEW_OE_EVIDENCE_STRING;

const char* OE_REQUIRED_CLAIMS[OE_REQUIRED_CLAIMS_COUNT] = {
    OE_CLAIM_ID_VERSION,
    OE_CLAIM_SECURITY_VERSION,
    OE_CLAIM_ATTRIBUTES,
    OE_CLAIM_UNIQUE_ID,
    OE_CLAIM_SIGNER_ID,
    OE_CLAIM_PRODUCT_ID,
    OE_CLAIM_FORMAT_UUID};

const char* OE_OPTIONAL_CLAIMS[OE_OPTIONAL_CLAIMS_COUNT] = {
    OE_CLAIM_TCB_STATUS,
    OE_CLAIM_TCB_DATE,
    OE_CLAIM_VALIDITY_FROM,
    OE_CLAIM_VALIDITY_UNTIL};

// Variables storing the verifier list.
static oe_plugin_list_node_t* verifiers = NULL;

// UUID for all OE reports generated by oe_get_report().
static const oe_uuid_t _uuid_legacy_report_remote = {
    OE_FORMAT_UUID_LEGACY_REPORT_REMOTE};

// verify report user data against peer certificate
static oe_result_t verify_sgx_report_user_data(
    uint8_t* key_buff,
    size_t key_buff_size,
    uint8_t* report_data)
{
    oe_result_t result = OE_FAILURE;
    oe_sha256_context_t sha256_ctx = {0};
    OE_SHA256 sha256;

    OE_TRACE_VERBOSE(
        "key_buff=[%s] \n oe_strlen(key_buff)=[%d]",
        key_buff,
        oe_strlen((const char*)key_buff));

    // create a hash of public key
    oe_memset_s(sha256.buf, OE_SHA256_SIZE, 0, OE_SHA256_SIZE);
    OE_CHECK(oe_sha256_init(&sha256_ctx));
    OE_CHECK(oe_sha256_update(&sha256_ctx, key_buff, key_buff_size));
    OE_CHECK(oe_sha256_final(&sha256_ctx, &sha256));

    // validate report's user data against hash(public key)
    if (memcmp(report_data, (uint8_t*)&sha256, OE_SHA256_SIZE) != 0)
    {
        for (int i = 0; i < OE_SHA256_SIZE; i++)
            OE_TRACE_VERBOSE(
                "[%d] report_data[0x%x] sha256=0x%x ",
                i,
                report_data[i],
                sha256.buf[i]);
        OE_RAISE_MSG(
            OE_QUOTE_HASH_MISMATCH,
            "hash of peer certificate's public key does not match report data",
            NULL);
    }
    result = OE_OK;
done:
    return result;
}

// Verify there is a matched claim for the public key */
static oe_result_t _verify_public_key_claim(
    oe_claim_t* claims,
    size_t claims_length,
    uint8_t* public_key_buffer,
    size_t public_key_buffer_size)
{
    oe_result_t result = OE_FAILURE;
    for (int i = (int)claims_length - 1; i >= 0; i--)
    {
        if (oe_strcmp(claims[i].name, OE_CLAIM_CUSTOM_CLAIMS_BUFFER) == 0)
        {
            if (claims[i].value_size == public_key_buffer_size &&
                memcmp(
                    claims[i].value,
                    public_key_buffer,
                    public_key_buffer_size) == 0)
            {
                OE_TRACE_VERBOSE("Found matched public key in claims");
                result = OE_OK;
                break;
            }
        }
        if (oe_strcmp(claims[i].name, OE_CLAIM_SGX_REPORT_DATA) == 0)
        {
            if (verify_sgx_report_user_data(
                    public_key_buffer,
                    public_key_buffer_size,
                    claims[i].value) == OE_OK)
            {
                OE_TRACE_VERBOSE("Found matched public key in claims");
                result = OE_OK;
                break;
            }
        }
    }
    return result;
}

// Finds the plugin node with the given ID. If found, the function
// will return the node and store the pointer of the previous node
// in prev (NULL for the head pointer). If not found, the function
// will return NULL.
oe_plugin_list_node_t* oe_attest_find_plugin(
    oe_plugin_list_node_t* head,
    const oe_uuid_t* target_format_id,
    oe_plugin_list_node_t** prev)
{
    oe_plugin_list_node_t* ret = NULL;
    oe_plugin_list_node_t* cur = NULL;

    if (prev)
        *prev = NULL;

    // Find a plugin for attestation type.
    cur = head;
    while (cur)
    {
        if (memcmp(
                &cur->plugin->format_id, target_format_id, sizeof(oe_uuid_t)) ==
            0)
        {
            ret = cur;
            break;
        }
        if (prev)
            *prev = cur;
        cur = cur->next;
    }

    return ret;
}

oe_result_t oe_attest_register_plugin(
    oe_plugin_list_node_t** list,
    oe_attestation_role_t* plugin,
    const void* configuration_data,
    size_t configuration_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_plugin_list_node_t* plugin_node = NULL;

    if (!list || !plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = oe_attest_find_plugin(*list, &plugin->format_id, NULL);
    if (plugin_node)
    {
        plugin_node = NULL;
        OE_RAISE(OE_ALREADY_EXISTS);
    }

    plugin_node = (oe_plugin_list_node_t*)oe_malloc(sizeof(*plugin_node));
    if (plugin_node == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Run the register function for the plugin.
    OE_CHECK(plugin->on_register(
        plugin, configuration_data, configuration_data_size));

    // Add to the plugin list.
    plugin_node->plugin = plugin;
    plugin_node->next = *list;
    *list = plugin_node;
    plugin_node = NULL;

    result = OE_OK;

done:
    oe_free(plugin_node);

    return result;
}

oe_result_t oe_attest_unregister_plugin(
    oe_plugin_list_node_t** list,
    oe_attestation_role_t* plugin)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_plugin_list_node_t* prev = NULL;
    oe_plugin_list_node_t* cur = NULL;

    if (!list || !plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Find the guid and remove it.
    cur = oe_attest_find_plugin(*list, &plugin->format_id, &prev);
    if (cur == NULL)
        OE_RAISE(OE_NOT_FOUND);

    if (prev != NULL)
        prev->next = cur->next;
    else
        *list = cur->next;

    // Run the unregister hook for the plugin.
    OE_CHECK(cur->plugin->on_unregister(cur->plugin));

    result = OE_OK;

done:
    oe_free(cur);
    return result;
}

oe_result_t oe_register_verifier_plugin(
    oe_verifier_t* plugin,
    const void* configuration_data,
    size_t configuration_data_size)
{
    return oe_attest_register_plugin(
        &verifiers,
        (oe_attestation_role_t*)plugin,
        configuration_data,
        configuration_data_size);
}

oe_result_t oe_unregister_verifier_plugin(oe_verifier_t* plugin)
{
    return oe_attest_unregister_plugin(
        &verifiers, (oe_attestation_role_t*)plugin);
}

static bool _check_claims(const oe_claim_t* claims, size_t claims_length)
{
    for (size_t i = 0; i < OE_REQUIRED_CLAIMS_COUNT; i++)
    {
        bool found = false;

        for (size_t j = 0; j < claims_length && !found; j++)
        {
            if (oe_strcmp(OE_REQUIRED_CLAIMS[i], claims[j].name) == 0)
            {
                found = true;
            }
        }

        if (!found)
        {
            OE_TRACE_ERROR("Missing required claim: %s", OE_REQUIRED_CLAIMS[i]);
            return false;
        }
    }
    return true;
}

oe_result_t oe_verify_evidence(
    const oe_uuid_t* format_id,
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
    oe_result_t _verify_evidence_result = OE_UNEXPECTED;
    oe_plugin_list_node_t* plugin_node;
    oe_verifier_t* verifier;
    const uint8_t* plugin_evidence = NULL;
    size_t plugin_evidence_size = 0;
    const uint8_t* plugin_endorsements = NULL;
    size_t plugin_endorsements_size = 0;
    uint8_t has_endorsements_baseline_policy = 0;

    if (!evidence_buffer || !evidence_buffer_size ||
        (!endorsements_buffer != !endorsements_buffer_size) ||
        (!claims != !claims_length))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure only one endorsements baseline policy can be specified.
    if (policies && policies_size > 0)
    {
        for (size_t i = 0; i < policies_size; ++i)
        {
            if (policies[i].type == OE_POLICY_ENDORSEMENTS_BASELINE)
            {
                if (has_endorsements_baseline_policy)
                {
                    OE_RAISE_MSG(
                        OE_VERIFY_BASELINE_INVALID,
                        "multiple endorsements baseline policies specified.",
                        NULL);
                }

                has_endorsements_baseline_policy = 1;
            }
        }
    }

    // fail the API call if both endorsements_buffer and
    // endorsements_baseline_policy are specified.
    if (endorsements_buffer && has_endorsements_baseline_policy)
    {
        OE_RAISE_MSG(
            OE_VERIFY_BASELINE_INVALID,
            "endorsements buffer conflicts with endorsements baseline policy",
            NULL);
    }

    if (!format_id)
    {
        // check whether evidence buffer structure is oe_report
        oe_report_header_t* report = (oe_report_header_t*)evidence_buffer;

        if (evidence_buffer_size >= sizeof(oe_report_header_t) &&
            report->version == OE_REPORT_HEADER_VERSION)
        {
            format_id = &_uuid_legacy_report_remote;
            plugin_evidence = evidence_buffer;
            plugin_evidence_size = evidence_buffer_size;
            plugin_endorsements = endorsements_buffer;
            plugin_endorsements_size = endorsements_buffer_size;
        }
        else
        {
            oe_attestation_header_t* evidence =
                (oe_attestation_header_t*)evidence_buffer;

            if (evidence_buffer_size < sizeof(oe_attestation_header_t) ||
                evidence->version != OE_ATTESTATION_HEADER_VERSION)
                OE_RAISE_MSG(
                    OE_INVALID_PARAMETER,
                    "Invalid attestation header version %d, expected %d",
                    evidence->version,
                    OE_ATTESTATION_HEADER_VERSION);

            if (evidence_buffer_size !=
                (evidence->data_size + sizeof(oe_attestation_header_t)))
                OE_RAISE_MSG(
                    OE_INVALID_PARAMETER,
                    "Evidence size is invalid. "
                    "Header data size: %d bytes, evidence buffer size: %d",
                    evidence->data_size,
                    evidence_buffer_size);

            if (endorsements_buffer)
            {
                oe_attestation_header_t* endorsements =
                    (oe_attestation_header_t*)endorsements_buffer;

                if (endorsements_buffer_size <
                        sizeof(oe_attestation_header_t) ||
                    endorsements->version != OE_ATTESTATION_HEADER_VERSION)
                    OE_RAISE_MSG(
                        OE_INVALID_PARAMETER,
                        "Invalid attestation header version %d, expected %d",
                        endorsements->version,
                        OE_ATTESTATION_HEADER_VERSION);

                if (endorsements_buffer_size !=
                    (endorsements->data_size + sizeof(oe_attestation_header_t)))
                    OE_RAISE_MSG(
                        OE_INVALID_PARAMETER,
                        "Endorsements buffer size is invalid. "
                        "Header data size: %d bytes, endorsements buffer size: "
                        "%d",
                        endorsements->data_size,
                        endorsements_buffer_size);

                if (memcmp(
                        &evidence->format_id,
                        &endorsements->format_id,
                        sizeof(evidence->format_id)) != 0)
                    OE_RAISE(OE_CONSTRAINT_FAILED);

                plugin_endorsements = endorsements->data;
                plugin_endorsements_size = endorsements->data_size;
            }

            plugin_evidence = evidence->data;
            plugin_evidence_size = evidence->data_size;
            format_id = &evidence->format_id;
        }
    }
    else
    {
        plugin_evidence = evidence_buffer;
        plugin_evidence_size = evidence_buffer_size;
        plugin_endorsements = endorsements_buffer;
        plugin_endorsements_size = endorsements_buffer_size;
    }

    plugin_node = oe_attest_find_plugin(verifiers, format_id, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    verifier = (oe_verifier_t*)plugin_node->plugin;
    OE_CHECK_NO_TCB_LEVEL(
        _verify_evidence_result,
        verifier->verify_evidence(
            verifier,
            plugin_evidence,
            plugin_evidence_size,
            plugin_endorsements,
            plugin_endorsements_size,
            policies,
            policies_size,
            claims,
            claims_length));

    if (claims && claims_length && !_check_claims(*claims, *claims_length))
    {
        verifier->free_claims(verifier, *claims, *claims_length);
        *claims = NULL;
        *claims_length = 0;
        OE_RAISE(OE_CONSTRAINT_FAILED);
    }

    result = _verify_evidence_result;

done:
    return result;
}

oe_result_t oe_verify_attestation_certificate_with_evidence(
    uint8_t* certificate_in_der,
    size_t certificate_in_der_size,
    oe_verify_claims_callback_t claim_verify_callback,
    void* arg)
{
    oe_result_t result = OE_FAILURE;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    result = oe_verify_attestation_certificate_with_evidence_v2(
        certificate_in_der,
        certificate_in_der_size,
        NULL,
        0,
        NULL,
        0,
        &claims,
        &claims_length);

    if (result != OE_OK)
        OE_RAISE_MSG(
            result,
            "oe_verify_attestation_certificate_with_evidence() failed with "
            "error = %s\n",
            oe_result_str(result));

    //---------------------------------------
    // call client to further check claims
    // --------------------------------------
    if (claim_verify_callback)
    {
        result = claim_verify_callback(claims, claims_length, arg);
        OE_CHECK(result);
        OE_TRACE_VERBOSE("claim_verify_callback() succeeded");
    }
    else
    {
        OE_TRACE_WARNING(
            "No claim_verify_callback provided in "
            "oe_verify_attestation_certificate_with_evidence call",
            NULL);
    }

done:
    oe_free_claims(claims, claims_length);
    return result;
}

oe_result_t oe_verify_attestation_certificate_with_evidence_v2(
    uint8_t* certificate_in_der,
    size_t certificate_in_der_size,
    uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
{
    oe_result_t result = OE_FAILURE;
    oe_cert_t cert = {0};
    uint8_t* report = NULL;
    size_t report_size = 0;
    oe_attestation_header_t* header = NULL;
    uint8_t* pub_key_buff = NULL;
    size_t pub_key_buff_size = KEY_BUFF_SIZE;

    const char* oid_array[] = {
        oid_oe_report, oid_new_oe_report, oid_oe_evidence, oid_new_oe_evidence};
    size_t oid_array_index = 0;
    size_t oid_array_count = OE_COUNTOF(oid_array);

    pub_key_buff = (uint8_t*)oe_malloc(KEY_BUFF_SIZE);
    if (!pub_key_buff)
        OE_RAISE(OE_OUT_OF_MEMORY);

    result =
        oe_cert_read_der(&cert, certificate_in_der, certificate_in_der_size);
    OE_CHECK_MSG(result, "certificate_in_der_size=%d", certificate_in_der_size);

    // validate the certificate signature
    result = oe_cert_verify(&cert, NULL, NULL, 0);
    OE_CHECK_MSG(
        result,
        "oe_cert_verify failed with error = %s\n",
        oe_result_str(result));

    //------------------------------------------------------------------------
    // Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    // set enclave to NULL because we are dealing only with remote report now
    //------------------------------------------------------------------------

    // determine the size of the extension
    while (oid_array_index < oid_array_count)
    {
        oe_result_t find_result = oe_cert_find_extension(
            &cert,
            (const char*)oid_array[oid_array_index],
            &report,
            &report_size);

        if (find_result == OE_NOT_FOUND)
        {
            oid_array_index++;
            continue;
        }

        if (find_result == OE_OK)
            break;

        OE_RAISE_MSG(find_result, "oe_cert_find_extension failed", NULL);
    }

    // if there is no match
    if (oid_array_index == oid_array_count)
        OE_RAISE_MSG(
            OE_FAILURE, "No expected certificate extension matched", NULL);

    // find the extension
    OE_TRACE_VERBOSE("extract_x509_report_extension() succeeded");

    if (oid_array_index >= 2) // oid_oe_evidence or oid_new_oe_evidence
    {
        // find the report version
        header = (oe_attestation_header_t*)report;
        if (header->version != OE_ATTESTATION_HEADER_VERSION)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "Invalid attestation header version %d, expected %d",
                header->version,
                OE_ATTESTATION_HEADER_VERSION);

        result = oe_verify_evidence(
            // The format ID parameter is NULL in this case, as the format ID is
            // embedded in the attestation header, which is always included in
            // an attestation certificate.
            NULL,
            report,
            report_size,
            endorsements_buffer,
            endorsements_buffer_size,
            policies,
            policies_size,
            claims,
            claims_length);
    }
    else // oid_oe_report or oid_new_oe_report
    {
        result = oe_verify_evidence(
            // The format ID is OE_FORMAT_UUID_LEGACY_REPORT_REMOTE for all OE
            // reports for remote attestation.
            &_uuid_legacy_report_remote,
            report,
            report_size,
            endorsements_buffer,
            endorsements_buffer_size,
            policies,
            policies_size,
            claims,
            claims_length);
    }

    OE_CHECK(result);
    OE_TRACE_VERBOSE("quote validation succeeded");

    // verify report data: hash(public key)
    // extract public key from the cert
    oe_memset_s(pub_key_buff, KEY_BUFF_SIZE, 0, KEY_BUFF_SIZE);
    result =
        oe_cert_write_public_key_pem(&cert, pub_key_buff, &pub_key_buff_size);
    OE_CHECK(result);
    OE_TRACE_VERBOSE(
        "oe_cert_write_public_key_pem pub_key_buf_size=%d", pub_key_buff_size);

    result = _verify_public_key_claim(
        *claims, *claims_length, pub_key_buff, pub_key_buff_size);
    OE_CHECK(result);
    OE_TRACE_VERBOSE("user data: hash(public key) validation passed", NULL);

done:
    oe_free(pub_key_buff);
    oe_cert_free(&cert);
    oe_free(report);
    return result;
}

static oe_result_t _get_uuid(
    const oe_claim_t* claims,
    size_t claims_length,
    oe_uuid_t* uuid)
{
    for (size_t i = 0; i < claims_length; i++)
    {
        if (oe_strcmp(claims[i].name, OE_CLAIM_FORMAT_UUID) == 0)
        {
            if (claims[i].value_size != sizeof(oe_uuid_t))
                return OE_CONSTRAINT_FAILED;

            *uuid = *((oe_uuid_t*)claims[i].value);
            return OE_OK;
        }
    }
    return OE_NOT_FOUND;
}

oe_result_t oe_free_claims(oe_claim_t* claims, size_t claims_length)
{
    oe_uuid_t uuid;
    oe_result_t result = OE_UNEXPECTED;
    oe_plugin_list_node_t* plugin_node;
    oe_verifier_t* verifier;

    if (!claims)
        return OE_OK;

    OE_CHECK(_get_uuid(claims, claims_length, &uuid));

    plugin_node = oe_attest_find_plugin(verifiers, &uuid, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    verifier = (oe_verifier_t*)plugin_node->plugin;
    OE_CHECK(verifier->free_claims(verifier, claims, claims_length));

    result = OE_OK;

done:
    return result;
}

// Count the number of plugins in the input list
static size_t _count_plugins(const oe_plugin_list_node_t* head)
{
    const oe_plugin_list_node_t* cur = head;
    size_t count = 0;
    while (cur)
    {
        cur = cur->next;
        count++;
    }
    return count;
}

oe_result_t oe_verifier_get_formats(
    oe_uuid_t** format_ids,
    size_t* format_ids_length)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t count = 0;
    oe_uuid_t* format_ids_buffer = NULL;

    if (!format_ids || !format_ids_length)
        OE_RAISE(OE_INVALID_PARAMETER);

    count = _count_plugins(verifiers);
    if (!count)
    {
        *format_ids = NULL;
        *format_ids_length = 0;
        result = OE_OK;
    }
    else
    {
        oe_plugin_list_node_t* cur = NULL;
        size_t idx = 0;

        format_ids_buffer = (oe_uuid_t*)oe_malloc(count * sizeof(oe_uuid_t));
        if (!format_ids_buffer)
            OE_RAISE(OE_OUT_OF_MEMORY);

        cur = verifiers;
        idx = 0;
        while (cur && idx < count)
        {
            memcpy(
                format_ids_buffer + idx,
                &cur->plugin->format_id,
                sizeof(oe_uuid_t));
            cur = cur->next;
            idx++;
        }

        // No plugin is expected to be added or removed
        // while oe_verifier_get_formats() runs.
        if (idx < count || cur)
            OE_RAISE(OE_UNEXPECTED);

        *format_ids = format_ids_buffer;
        *format_ids_length = count;
        format_ids_buffer = NULL;
        result = OE_OK;
    }

done:
    oe_free(format_ids_buffer);
    return result;
}

oe_result_t oe_verifier_free_formats(oe_uuid_t* format_ids)
{
    oe_free(format_ids);
    return OE_OK;
}

oe_result_t oe_verifier_get_format_settings(
    const oe_uuid_t* format_id,
    uint8_t** settings,
    size_t* settings_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_plugin_list_node_t* plugin_node = NULL;
    oe_verifier_t* plugin = NULL;

    if (!format_id || !settings || !settings_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = oe_attest_find_plugin(verifiers, format_id, NULL);
    if (!plugin_node)
        OE_RAISE(OE_NOT_FOUND);

    plugin = (oe_verifier_t*)plugin_node->plugin;
    OE_CHECK(plugin->get_format_settings(plugin, settings, settings_size));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_verifier_free_format_settings(uint8_t* settings)
{
    oe_free(settings);
    return OE_OK;
}

oe_result_t oe_find_verifier_plugin(
    const oe_uuid_t* format_id,
    oe_verifier_t** verifier_plugin)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_plugin_list_node_t* plugin_node = NULL;

    if (!format_id || !verifier_plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = oe_attest_find_plugin(verifiers, format_id, NULL);
    if (!plugin_node)
        OE_RAISE(OE_NOT_FOUND);

    *verifier_plugin = (oe_verifier_t*)plugin_node->plugin;

    result = OE_OK;

done:
    return result;
}
