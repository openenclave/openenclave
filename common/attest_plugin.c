// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/plugin.h>
#include <openenclave/bits/defs.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

const char* OE_REQUIRED_CLAIMS[OE_REQUIRED_CLAIMS_COUNT] = {
    OE_CLAIM_ID_VERSION,
    OE_CLAIM_SECURITY_VERSION,
    OE_CLAIM_ATTRIBUTES,
    OE_CLAIM_UNIQUE_ID,
    OE_CLAIM_SIGNER_ID,
    OE_CLAIM_PRODUCT_ID,
    OE_CLAIM_PLUGIN_UUID};

const char* OE_OPTIONAL_CLAIMS[OE_OPTIONAL_CLAIMS_COUNT] = {
    OE_CLAIM_VALIDITY_FROM,
    OE_CLAIM_VALIDITY_UNTIL};

/**
 * Header that the OE runtime puts ontop of the attestation plugins.
 */
typedef struct _oe_attestation_header
{
    /* Set to OE_ATTESTATION_HEADER_VERSION. */
    uint32_t version;

    /* UUID to identify format. */
    oe_uuid_t format_id;

    /* Size of evidence/endorsements sent to the plugin. */
    uint64_t data_size;

    /* The actual data */
    uint8_t data[];

    /* data_size bytes that follows the header will be sent to a plugin. */
} oe_attestation_header_t;

// Struct definition to represent the list of plugins.
struct plugin_list_node_t
{
    oe_attestation_role_t* plugin;
    struct plugin_list_node_t* next;
};

// Variables storing the attester and verifier lists.
struct plugin_list_node_t* attesters = NULL;
struct plugin_list_node_t* verifiers = NULL;

// Finds the plugin node with the given ID. If found, the function
// will return the node and store the pointer of the previous node
// in prev (NULL for the head pointer). If not found, the function
// will return NULL.
static struct plugin_list_node_t* _find_plugin(
    struct plugin_list_node_t* head,
    const oe_uuid_t* target_format_id,
    struct plugin_list_node_t** prev)
{
    struct plugin_list_node_t* ret = NULL;
    struct plugin_list_node_t* cur = NULL;

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

static oe_result_t _register_plugin(
    struct plugin_list_node_t** list,
    oe_attestation_role_t* plugin,
    const void* config_data,
    size_t config_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* plugin_node = NULL;

    if (!list || !plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = _find_plugin(*list, &plugin->format_id, NULL);
    if (plugin_node)
    {
        plugin_node = NULL;
        OE_RAISE(OE_ALREADY_EXISTS);
    }

    plugin_node = (struct plugin_list_node_t*)oe_malloc(sizeof(*plugin_node));
    if (plugin_node == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Run the register function for the plugin.
    OE_CHECK(plugin->on_register(plugin, config_data, config_data_size));

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

static oe_result_t _unregister_plugin(
    struct plugin_list_node_t** list,
    oe_attestation_role_t* plugin)
{
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* prev = NULL;
    struct plugin_list_node_t* cur = NULL;

    if (!list || !plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Find the guid and remove it.
    cur = _find_plugin(*list, &plugin->format_id, &prev);
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

oe_result_t oe_register_attester(
    oe_attester_t* plugin,
    const void* config_data,
    size_t config_data_size)
{
    return _register_plugin(
        &attesters,
        (oe_attestation_role_t*)plugin,
        config_data,
        config_data_size);
}

oe_result_t oe_register_verifier(
    oe_verifier_t* plugin,
    const void* config_data,
    size_t config_data_size)
{
    return _register_plugin(
        &verifiers,
        (oe_attestation_role_t*)plugin,
        config_data,
        config_data_size);
}

oe_result_t oe_unregister_attester(oe_attester_t* plugin)
{
    return _unregister_plugin(&attesters, (oe_attestation_role_t*)plugin);
}

oe_result_t oe_unregister_verifier(oe_verifier_t* plugin)
{
    return _unregister_plugin(&verifiers, (oe_attestation_role_t*)plugin);
}

static oe_result_t _wrap_with_header(
    const oe_uuid_t* format_id,
    const uint8_t* data,
    size_t data_size,
    uint8_t** total_data,
    size_t* total_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_attestation_header_t* header;

    OE_CHECK(oe_safe_add_sizet(sizeof(*header), data_size, total_data_size));

    *total_data = (uint8_t*)oe_malloc(*total_data_size);
    if (*total_data == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    header = (oe_attestation_header_t*)*total_data;
    header->version = OE_ATTESTATION_HEADER_VERSION;
    header->format_id = *format_id;
    header->data_size = data_size;
    memcpy(header->data, data, data_size);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_evidence(
    const oe_uuid_t* format_id,
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
    struct plugin_list_node_t* plugin_node = NULL;
    oe_attester_t* plugin = NULL;
    uint8_t* plugin_evidence = NULL;
    size_t plugin_evidence_size = 0;
    uint8_t* plugin_endorsements = NULL;
    size_t plugin_endorsements_size = 0;
    uint8_t* total_evidence_buf = NULL;
    size_t total_evidence_size = 0;
    uint8_t* total_endorsements_buf = NULL;
    size_t total_endorsements_size = 0;

    if (!format_id || !evidence_buffer || !evidence_buffer_size ||
        (endorsements_buffer && !endorsements_buffer_size) ||
        (!endorsements_buffer && endorsements_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Find a plugin for attestation type and run its get_evidence.
    plugin_node = _find_plugin(attesters, format_id, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    // Now get the evidence and endorsements (if desired).
    plugin = (oe_attester_t*)plugin_node->plugin;
    OE_CHECK(plugin->get_evidence(
        plugin,
        flags,
        custom_claims,
        custom_claims_length,
        opt_params,
        opt_params_size,
        &plugin_evidence,
        &plugin_evidence_size,
        endorsements_buffer ? &plugin_endorsements : NULL,
        endorsements_buffer ? &plugin_endorsements_size : NULL));

    // Wrap the attestation header around the evidence.
    OE_CHECK(_wrap_with_header(
        format_id,
        plugin_evidence,
        plugin_evidence_size,
        &total_evidence_buf,
        &total_evidence_size));

    if (endorsements_buffer)
    {
        OE_CHECK(_wrap_with_header(
            format_id,
            plugin_endorsements,
            plugin_endorsements_size,
            &total_endorsements_buf,
            &total_endorsements_size));
    }

    // Finally, set the out parameters.
    *evidence_buffer = total_evidence_buf;
    *evidence_buffer_size = total_evidence_size;
    total_evidence_buf = NULL;

    if (endorsements_buffer)
    {
        *endorsements_buffer = total_endorsements_buf;
        *endorsements_buffer_size = total_endorsements_size;
        total_endorsements_buf = NULL;
    }

    result = OE_OK;

done:
    if (plugin && plugin_evidence)
    {
        plugin->free_evidence(plugin, plugin_evidence);
        if (plugin_endorsements)
            plugin->free_endorsements(plugin, plugin_endorsements);
    }
    if (total_evidence_buf != NULL)
        oe_free(total_evidence_buf);
    if (total_endorsements_buf != NULL)
        oe_free(total_endorsements_buf);
    return result;
}

oe_result_t oe_free_evidence(uint8_t* evidence_buffer)
{
    oe_free(evidence_buffer);
    return OE_OK;
}

oe_result_t oe_free_endorsements(uint8_t* evidence_buffer)
{
    oe_free(evidence_buffer);
    return OE_OK;
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
    struct plugin_list_node_t* plugin_node;
    oe_verifier_t* verifier;
    oe_attestation_header_t* evidence =
        (oe_attestation_header_t*)evidence_buffer;
    oe_attestation_header_t* endorsements =
        (oe_attestation_header_t*)endorsements_buffer;

    if (!evidence_buffer || evidence_buffer_size < sizeof(*evidence) ||
        (endorsements_buffer &&
         endorsements_buffer_size < sizeof(*endorsements)))
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = _find_plugin(verifiers, &evidence->format_id, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    if (endorsements && memcmp(
                            &evidence->format_id,
                            &endorsements->format_id,
                            sizeof(evidence->format_id)) != 0)
        OE_RAISE(OE_CONSTRAINT_FAILED);

    verifier = (oe_verifier_t*)plugin_node->plugin;
    OE_CHECK(verifier->verify_evidence(
        verifier,
        evidence->data,
        evidence->data_size,
        endorsements ? endorsements->data : NULL,
        endorsements ? endorsements->data_size : 0,
        policies,
        policies_size,
        claims,
        claims_length));

    if (!_check_claims(*claims, *claims_length))
    {
        verifier->free_claims_list(verifier, *claims, *claims_length);
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
        if (oe_strcmp(claims[i].name, OE_CLAIM_PLUGIN_UUID) == 0)
        {
            if (claims[i].value_size != sizeof(oe_uuid_t))
                return OE_CONSTRAINT_FAILED;

            *uuid = *((oe_uuid_t*)claims[i].value);
            return OE_OK;
        }
    }
    return OE_NOT_FOUND;
}

oe_result_t oe_free_claims_list(oe_claim_t* claims, size_t claims_length)
{
    oe_uuid_t uuid;
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* plugin_node;
    oe_verifier_t* verifier;

    if (!claims)
        return OE_OK;

    OE_CHECK(_get_uuid(claims, claims_length, &uuid));

    plugin_node = _find_plugin(verifiers, &uuid, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    verifier = (oe_verifier_t*)plugin_node->plugin;
    OE_CHECK(verifier->free_claims_list(verifier, claims, claims_length));

    result = OE_OK;

done:
    return result;
}
