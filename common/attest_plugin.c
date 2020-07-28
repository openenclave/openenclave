// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/hexdump.h>
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

#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/internal/plugin.h>

#define KEY_BUFF_SIZE 2048

static const char* oid_oe_evidence = X509_OID_FOR_OE_EVIDENCE_STRING;

const char* OE_REQUIRED_CLAIMS[OE_REQUIRED_CLAIMS_COUNT] = {
    OE_CLAIM_ID_VERSION,
    OE_CLAIM_SECURITY_VERSION,
    OE_CLAIM_ATTRIBUTES,
    OE_CLAIM_UNIQUE_ID,
    OE_CLAIM_SIGNER_ID,
    OE_CLAIM_PRODUCT_ID,
    OE_CLAIM_FORMAT_UUID};

const char* OE_OPTIONAL_CLAIMS[OE_OPTIONAL_CLAIMS_COUNT] = {
    OE_CLAIM_VALIDITY_FROM,
    OE_CLAIM_VALIDITY_UNTIL};

// Variables storing the verifier list.
static oe_plugin_list_node_t* verifiers = NULL;

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
        if (oe_strcmp(claims[i].name, OE_CLAIM_CUSTOM_CLAIMS) == 0)
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
    if (plugin_node != NULL)
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
            return false;
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
    oe_plugin_list_node_t* plugin_node;
    oe_verifier_t* verifier;
    const uint8_t* plugin_evidence = NULL;
    size_t plugin_evidence_size = 0;
    const uint8_t* plugin_endorsements = NULL;
    size_t plugin_endorsements_size = 0;

    if (!evidence_buffer || !evidence_buffer_size ||
        (!endorsements_buffer && endorsements_buffer_size) ||
        (endorsements_buffer && !endorsements_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!format_id)
    {
        oe_attestation_header_t* evidence =
            (oe_attestation_header_t*)evidence_buffer;

        if (evidence_buffer_size < sizeof(oe_attestation_header_t) ||
            evidence->version != OE_ATTESTATION_HEADER_VERSION)
            OE_RAISE(OE_INVALID_PARAMETER);

        if (endorsements_buffer)
        {
            oe_attestation_header_t* endorsements =
                (oe_attestation_header_t*)endorsements_buffer;

            if (endorsements_buffer_size < sizeof(oe_attestation_header_t) ||
                endorsements->version != OE_ATTESTATION_HEADER_VERSION)
                OE_RAISE(OE_INVALID_PARAMETER);

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
    OE_CHECK(verifier->verify_evidence(
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

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_verify_attestation_certificate_with_evidence(
    uint8_t* cert_in_der,
    size_t cert_in_der_len,
    oe_verify_claims_callback_t claim_verify_callback,
    void* arg)
{
    oe_result_t result = OE_FAILURE;
    oe_cert_t cert = {0};
    uint8_t* report = NULL;
    size_t report_size = 0;
    oe_report_header_t* header = NULL;
    uint8_t* pub_key_buff = NULL;
    size_t pub_key_buff_size = KEY_BUFF_SIZE;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    pub_key_buff = (uint8_t*)oe_malloc(KEY_BUFF_SIZE);
    if (!pub_key_buff)
        OE_RAISE(OE_OUT_OF_MEMORY);

    result = oe_cert_read_der(&cert, cert_in_der, cert_in_der_len);
    OE_CHECK_MSG(result, "cert_in_der_len=%d", cert_in_der_len);

    // validate the certificate signature
    result = oe_cert_verify(&cert, NULL, NULL, 0);
    OE_CHECK_MSG(
        result,
        "oe_cert_verify failed with error = %s\n",
        oe_result_str(result));

    //------------------------------------------------------------------------
    // Validate the report's trustworthiness
    //------------------------------------------------------------------------

    // determine the size of the extension
    if (oe_cert_find_extension(
            &cert, (const char*)oid_oe_evidence, NULL, &report_size) !=
        OE_BUFFER_TOO_SMALL)
        OE_RAISE(OE_FAILURE);

    report = (uint8_t*)oe_malloc(report_size);
    if (!report)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // find the extension
    OE_CHECK(oe_cert_find_extension(
        &cert, (const char*)oid_oe_evidence, report, &report_size));
    OE_TRACE_VERBOSE("extract_x509_report_extension() succeeded");

    // find the report version
    header = (oe_report_header_t*)report;
    if (header->version != OE_ATTESTATION_HEADER_VERSION)
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid report version", NULL);

    result = oe_verify_evidence(
        // rely on the format UUID in the header. For attestation
        // certificate, the report should always include the header.
        NULL,
        report,
        report_size,
        NULL,
        0,
        NULL,
        0,
        &claims,
        &claims_length);
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
        claims, claims_length, pub_key_buff, pub_key_buff_size);
    OE_CHECK(result);
    OE_TRACE_VERBOSE("user data: hash(public key) validation passed", NULL);

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
    oe_free(pub_key_buff);
    oe_free_claims(claims, claims_length);
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

oe_result_t oe_verifier_get_formats(oe_uuid_t** formats, size_t* formats_length)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t count = 0;
    oe_uuid_t* formats_buf = NULL;

    if (!formats || !formats_length)
        OE_RAISE(OE_INVALID_PARAMETER);

    count = _count_plugins(verifiers);
    if (!count)
    {
        *formats = NULL;
        *formats_length = 0;
        result = OE_OK;
    }
    else
    {
        oe_plugin_list_node_t* cur = NULL;
        size_t idx = 0;

        formats_buf = (oe_uuid_t*)oe_malloc(count * sizeof(oe_uuid_t));
        if (!formats_buf)
            OE_RAISE(OE_OUT_OF_MEMORY);

        cur = verifiers;
        idx = 0;
        while (cur && idx < count)
        {
            memcpy(
                formats_buf + idx, &cur->plugin->format_id, sizeof(oe_uuid_t));
            cur = cur->next;
            idx++;
        }

        // No plugin is expected to be added or removed
        // while oe_verifier_get_formats() runs.
        if (idx < count || cur)
            OE_RAISE(OE_UNEXPECTED);

        *formats = formats_buf;
        *formats_length = count;
        formats_buf = NULL;
        result = OE_OK;
    }

done:
    if (formats_buf)
        oe_free(formats_buf);
    return result;
}

oe_result_t oe_verifier_free_formats(oe_uuid_t* formats)
{
    oe_free(formats);
    return OE_OK;
}

oe_result_t oe_verifier_get_format_settings(
    const oe_uuid_t* format,
    uint8_t** settings,
    size_t* settings_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_plugin_list_node_t* plugin_node = NULL;
    oe_verifier_t* plugin = NULL;

    if (!format || !settings || !settings_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = oe_attest_find_plugin(verifiers, format, NULL);
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
