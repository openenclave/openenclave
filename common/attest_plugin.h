// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_ATTEST_PLUGIN_H
#define _OE_COMMON_ATTEST_PLUGIN_H

#include <openenclave/bits/defs.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

#include <openenclave/internal/plugin.h>

OE_EXTERNC_BEGIN

/**
 * Note: V1 is OE_REPORT_HEADER_VERSION, for legacy report headers
 * of type oe_report_header_t.
 *
 * V2 is for legacy attestation headers of type oe_attestation_header_t.
 * For SGX local and remote attestation, the evidence requires a legacy
 * report header of type oe_report_header_t to prefix the SGX report or
 * quote.
 *
 * V3 is the current version. Its also for attestation headers of type
 * oe_attestation_header_t. SGX report or quote will not be prefixed with
 * a legacy header of type oe_report_header_t.
 *
 * Only the latest header version is supported.
 */
#define OE_ATTESTATION_HEADER_VERSION (3)

/**
 * Evidence header: the structure that the OE SDK runtime puts on top of
 * evidence data, when oe_get_evidence() is asked to include the format ID
 * with the evidence.
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
typedef struct _plugin_list_node_t
{
    oe_attestation_role_t* plugin;
    struct _plugin_list_node_t* next;
} oe_plugin_list_node_t;

/**
 * Finds the plugin node with the given format ID from the given list.
 *
 * @param[in] head The head of the plugin list from which to find the plugin.
 * @param[in] target_format_id The format ID of the plugin to be found.
 * @param[out] prev If not NULL, holds the the previous node (if any) pointing
 * to the head node.
 * @retval if the requested plugin is found, the function returns the node
 * and stores the pointer of the previous node in prev (NULL for the head
 * pointer). If not found, the function returns NULL.
 */
oe_plugin_list_node_t* oe_attest_find_plugin(
    oe_plugin_list_node_t* head,
    const oe_uuid_t* target_format_id,
    oe_plugin_list_node_t** prev);

/**
 * Registers the given plugin in the given list.
 *
 * @param[in] list The given list in which to register the given plugin.
 * @param[in] plugin The given plugin to be registered.
 * @param[in] configuration_data The optional configuration data for the plugin.
 * @param[in] configuration_data_size The size of the configuration data.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_attest_register_plugin(
    oe_plugin_list_node_t** list,
    oe_attestation_role_t* plugin,
    const void* configuration_data,
    size_t configuration_data_size);

/**
 * Unregisters the given plugin from the given list.
 *
 * @param[in] list The given list from which to unregister the given plugin.
 * @param[in] plugin The given plugin to be unregistered.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_attest_unregister_plugin(
    oe_plugin_list_node_t** list,
    oe_attestation_role_t* plugin);

OE_EXTERNC_END

#endif /* _OE_COMMON_ATTEST_PLUGIN_H */
