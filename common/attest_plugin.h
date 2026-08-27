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
 * Identifies which of the two plugin registries - attesters or verifiers - an
 * operation applies to. In-flight call counts are tracked separately per role
 * so that a verifier call cannot block an attester shutdown, or vice versa.
 */
typedef enum _oe_attest_role_type
{
    OE_ATTEST_ROLE_ATTESTER = 0,
    OE_ATTEST_ROLE_VERIFIER = 1,
    OE_ATTEST_ROLE_COUNT = 2
} oe_attest_role_type_t;

/**
 * Unregisters the given plugin from the given list.
 *
 * @param[in] role_type The registry the plugin belongs to.
 * @param[in] list The given list from which to unregister the given plugin.
 * @param[in] plugin The given plugin to be unregistered.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUSY A call through a plugin of this role is in flight.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_attest_unregister_plugin(
    oe_attest_role_type_t role_type,
    oe_plugin_list_node_t** list,
    oe_attestation_role_t* plugin);

/**
 * Looks up the plugin with the given format ID and takes a reference on the
 * plugin registry.
 *
 * Callers must use this function - rather than a bare oe_attest_find_plugin()
 * - whenever the returned plugin is subsequently dispatched to. The reference
 * prevents the plugin from being unregistered, and therefore from being freed
 * by a concurrent oe_attester_shutdown() or oe_verifier_shutdown(), while the
 * call is in flight.
 *
 * @param[in] role_type The registry \p list belongs to.
 * @param[in] list The plugin list to search.
 * @param[in] format_id The format ID of the plugin to be found.
 * @param[out] plugin On success, receives the plugin.
 * @retval OE_OK The plugin was found and a reference was taken. The caller
 * must release it with oe_attest_release_plugin().
 * @retval OE_NOT_FOUND No plugin is registered for \p format_id.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 */
oe_result_t oe_attest_acquire_plugin(
    oe_attest_role_type_t role_type,
    oe_plugin_list_node_t* const* list,
    const oe_uuid_t* format_id,
    oe_attestation_role_t** plugin);

/**
 * Takes a reference on the plugin registry without looking up a plugin.
 *
 * Used by callers that walk a plugin list. Holding a reference keeps the list
 * nodes alive for the duration of the walk.
 *
 * @param[in] role_type The registry to take a reference on.
 * @retval OE_OK A reference was taken. The caller must release it with
 * oe_attest_release_plugin().
 * @retval OE_INVALID_PARAMETER \p role_type is invalid.
 */
oe_result_t oe_attest_acquire_registry(oe_attest_role_type_t role_type);

/**
 * Releases a reference taken by oe_attest_acquire_plugin() or
 * oe_attest_acquire_registry().
 *
 * @param[in] role_type The registry the reference was taken on.
 */
void oe_attest_release_plugin(oe_attest_role_type_t role_type);

/**
 * Begins a shutdown of the given plugin registry.
 *
 * On success the registry lock is held by the caller, so no further reference
 * can be taken until oe_attest_end_shutdown() is called. This lets a caller
 * unregister every plugin and then free the plugin storage as one atomic
 * sequence: checking for in-flight calls per unregistration instead would let
 * a shutdown abort partway through, leaving some plugins unregistered while
 * the storage stays allocated - a state that oe_attester_initialize() and
 * oe_verifier_initialize() would not repair, permanently breaking attestation
 * for the affected formats.
 *
 * The registry lock is recursive, so oe_attest_unregister_plugin() may be
 * called while it is held.
 *
 * @param[in] role_type The registry being shut down.
 * @retval OE_OK The lock is held; the caller must call
 * oe_attest_end_shutdown() when done.
 * @retval OE_BUSY A call through a plugin of this role is in flight. The
 * registry has not been modified and the lock is not held.
 * @retval OE_INVALID_PARAMETER \p role_type is invalid.
 */
oe_result_t oe_attest_begin_shutdown(oe_attest_role_type_t role_type);

/**
 * Ends a shutdown begun by a successful oe_attest_begin_shutdown(), releasing
 * the registry lock.
 */
void oe_attest_end_shutdown(void);

OE_EXTERNC_END

#endif /* _OE_COMMON_ATTEST_PLUGIN_H */
