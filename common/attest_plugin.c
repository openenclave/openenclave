// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>

#include "attest_plugin.h"
#include "common.h"

#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/internal/plugin.h>

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

    if (!_check_claims(*claims, *claims_length))
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
