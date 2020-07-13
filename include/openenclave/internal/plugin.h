// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file plugin.h
 *
 * This file defines the programming interface for developing
 * attester or verifier plugins for supporting alternative evidence formats.
 *
 */

#ifndef _OE_ATTESTATION_PLUGIN_H
#define _OE_ATTESTATION_PLUGIN_H

#ifdef OE_BUILD_ENCLAVE
// The attester related definitions are only available for the enclave.
#include <openenclave/attestation/attester.h>
#endif
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Struct that defines the base structure of each attestation role plugin.
 * Each plugin will have an UUID to indicate what evidence format
 * is supported and have functions for registering/unregistering the plugin.
 * Each plugin will also define the required function for their
 * specific role (i.e., `get_evidence` for the attester and `verifiy_evidence`
 * for the verifier).
 */
typedef struct _oe_attestation_role oe_attestation_role_t;
struct _oe_attestation_role
{
    /**
     * The UUID indicating what evidence format is supported.
     */
    oe_uuid_t format_id;

    /**
     * The function that gets executed when the plugin is registered.
     *
     * @experimental
     *
     * @param[in] context A pointer to the attestation role struct.
     * @param[in] configuration_data An optional pointer to the configuration
     * data.
     * @param[in] configuration_data_size The size in bytes of
     * configuration_data.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*on_register)(
        oe_attestation_role_t* context,
        const void* configuration_data,
        size_t configuration_data_size);

    /**
     * The function that gets executed when the plugin is unregistered.
     *
     * @experimental
     *
     * @param[in] context A pointer to the attestation role struct.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*on_unregister)(oe_attestation_role_t* context);
};

#ifdef OE_BUILD_ENCLAVE

/**
 * The attester attestation role. The attester is reponsible for generating the
 * attestation evidence and must implement the functions below.
 */
typedef struct _oe_attester oe_attester_t;
struct _oe_attester
{
    /**
     * The base attestation role with the common functions for each plugin.
     */
    oe_attestation_role_t base;

    /**
     * Generates the attestation evidence, which is defined as the data
     * produced by the enclave. The caller may pass in custom claims, which
     * must be attached to the evidence and then cryptographically signed.
     *
     * Note that many callers of `get_evidence` will send the results over
     * the network, so the output must be in a serialized form.
     *
     * @experimental
     *
     * @param[in] context A pointer to the attester plugin struct.
     * @param[in] custom_claims The optional custom claims buffer.
     * @param[in] custom_claims_size The number of bytes in the custom claims
     * buffer.
     * @param[in] opt_params The optional plugin-specific input parameters.
     * @param[in] opt_params_size The size of opt_params in bytes.
     * @param[out] evidence_buffer An output pointer that will be assigned the
     * address of the evidence buffer.
     * @param[out] evidence_buffer_size A pointer that points to the size of the
     * evidence buffer in bytes.
     * @param[out] endorsements_buffer An output pointer that will be assigned
     * the address of the endorsements buffer.
     * @param[out] endorsements_buffer_size A pointer that points to the size of
     * the endorsements buffer in bytes.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*get_evidence)(
        oe_attester_t* context,
        const void* custom_claims,
        size_t custom_claims_size,
        const void* opt_params,
        size_t opt_params_size,
        uint8_t** evidence_buffer,
        size_t* evidence_buffer_size,
        uint8_t** endorsements_buffer,
        size_t* endorsements_buffer_size);

    /**
     * Creates a legacy OE report to be used in SGX local or remote attestation.
     * The report shall contain the data given by the report_data parameter.
     * This entry point is for the OE SDK framework to implement legacy API
     * oe_get_report_v2().
     *
     * @experimental
     *
     * @param[in] context A pointer to the attester plugin struct.
     * @param[in] flags Specifying default value (0) generates a report for
     * local attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION
     * generates a report for remote attestation.
     * @param[in] report_data The report data that will be included in the
     * report.
     * @param[in] report_data_size The size of the **report_data** in bytes.
     * @param[in] opt_params Optional additional parameters needed for the
     * current enclave type. For SGX, this can be sgx_target_info_t for local
     * attestation.
     * @param[in] opt_params_size The size of the **opt_params** buffer.
     * @param[out] report_buffer This points to the resulting report upon
     * success.
     * @param[out] report_buffer_size This is set to the
     * size of the report buffer on success.
     *
     * @retval OE_OK The report was successfully created.
     * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
     * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
     * @retval An appropriate error code on failure.
     *
     */
    oe_result_t (*get_report)(
        oe_attester_t* context,
        uint32_t flags,
        const uint8_t* report_data,
        size_t report_data_size,
        const void* opt_params,
        size_t opt_params_size,
        uint8_t** report_buffer,
        size_t* report_buffer_size);

    /**
     * Frees the generated attestation evidence.
     *
     * @experimental
     *
     * @param[in] context A pointer to the attester plugin struct.
     * @param[in] evidence_buffer A pointer to the evidence buffer.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (
        *free_evidence)(oe_attester_t* context, uint8_t* evidence_buffer);

    /**
     * Frees the generated attestation endorsements.
     *
     * @experimental
     *
     * @param[in] context A pointer to the attester plugin struct.
     * @param[in] endorsements_buffer A pointer to the endorsements buffer.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*free_endorsements)(
        oe_attester_t* context,
        uint8_t* endorsements_buffer);
};

#endif // OE_BUILD_ENCLAVE

/**
 * The verifier attestation role. The verifier is reponsible for verifying the
 * attestation evidence and must implement the functions below.
 */
typedef struct _oe_verifier oe_verifier_t;
struct _oe_verifier
{
    /**
     * The base attestation role with the common functions for each plugin.
     */
    oe_attestation_role_t base;

    /**
     *
     * Gets the optional settings data for the input evidence format.
     *
     * @experimental
     *
     * @param[in] context A pointer to the verifier plugin struct.
     * @param[in] format The format for which to retrieve the optional settings.
     * @param[out] settings An output pointer that will be assigned the address
     * of a dynamically allocated buffer that holds the returned settings. This
     * pointer can be assigned a NULL value if there is no settings needed.
     * @param[out] settings_size A pointer that points to the size of the
     * returned format settings buffer (number of bytes).
     * @retval OE_OK on success.
     * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
     * @retval other appropriate error code.
     */
    oe_result_t (*get_format_settings)(
        oe_verifier_t* context,
        uint8_t** settings,
        size_t* settings_size);

    /**
     * Verifies the attestation evidence and returns the claims contained in
     * the evidence.
     *
     * Each plugin must return the following required claims:
     *  - id_version (uint32_t)
     *      - Version number. Must be 1.
     *  - security_version (uint32_t)
     *      - Security version of the enclave. (ISVN for SGX).
     *  - attributes (uint64_t)
     *      - Attributes flags for the evidence:
     *          - OE_EVIDENCE_ATTRIBUTES_SGX_DEBUG: The evidence is for a debug
     *            mode enclave.
     *          - OE_EVIDENCE_ATTRIBUTES_SGX_REMOTE: The evidence can be used
     *            for remote attestation
     * - unique_id (uint8_t[32])
     *      - The unique ID for the enclave (MRENCLAVE for SGX).
     * - signer_id (uint8_t[32])
     *      - The signer ID for the enclave (MRSIGNER for SGX).
     * - product_id (uint8_t[32])
     *      - The product ID for the enclave (ISVPRODID for SGX).
     * - validity_from (oe_datetime_t)
     *      - The earliest datetime from which the evidence and endorsements are
     *        both valid.
     * - validity_until (oe_datetime_t)
     *      - The latest datetime until which the evidence and endorsements are
     *        both valid.
     * - format_uuid (uint8_t[16])
     *      - The format UUID of the verified evidence.
     *
     * The plugin is responsible for handling endianness and ensuring that the
     * data from the raw evidence converted properly for each platform.
     *
     * @experimental
     *
     * @param[in] context A pointer to the verifier plugin struct.
     * @param[in] evidence_buffer The evidence buffer.
     * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
     * @param[in] endorsements_buffer The endorsements buffer.
     * @param[in] endorsements_buffer_size The size of endorsements_buffer in
     * bytes.
     * @param[in] policies A list of policies to use.
     * @param[in] policies_size The size of the policy list.
     * @param[out] claims The list of base + custom claims.
     * @param[out] claims_length The length of the claims list.
     * @retval OE_OK on success.
     * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*verify_evidence)(
        oe_verifier_t* context,
        const uint8_t* evidence_buffer,
        size_t evidence_buffer_size,
        const uint8_t* endorsements_buffer,
        size_t endorsements_buffer_size,
        const oe_policy_t* policies,
        size_t policies_size,
        oe_claim_t** claims,
        size_t* claims_length);

    /**
     * Verify the integrity of the legacy report and its signature.
     *
     * This entry point verifies that the report signature is valid.
     * If the report is local, it verifies that it is correctly signed by the
     * enclave platform. If the report is remote, it verifies that the signing
     * authority is rooted to a trusted authority such as the enclave platform
     * manufacturer.
     *
     * @experimental
     *
     * @param[in] context A pointer to the verifier plugin struct.
     * @param[in] report The buffer containing the report to verify.
     * @param[in] report_size The size of the **report** buffer.
     * @param[out] parsed_report Optional **oe_report_t** structure to populate
     * with the report properties in a standard format.
     *
     * @retval OE_OK The report was successfully created.
     * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
     * @retval An appropriate error code on failure.
     *
     */
    oe_result_t (*verify_report)(
        oe_verifier_t* context,
        const uint8_t* report,
        size_t report_size,
        oe_report_t* parsed_report);

    /**
     * Frees the generated claims.
     *
     * @experimental
     *
     * @param[in] context A pointer to the verifier plugin struct.
     * @param[in] claims The list of claims.
     * @param[in] claims_length The length of the claims list.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*free_claims)(
        oe_verifier_t* context,
        oe_claim_t* claims,
        size_t claims_length);
};

#ifdef OE_BUILD_ENCLAVE

/**
 * oe_register_attester_plugin
 *
 * Registers a new attester plugin and optionally configures it with plugin
 * specific configuration data. The function will fail if a plugin for the
 * same UUID has already been registered.
 *
 * This is available in the enclave only.
 *
 * @experimental
 *
 * @param[in] plugin A pointer to the attestation plugin struct. Note that this
 * will not copy the contents of the plugin struct, so the struct must be kept
 * valid until the plugin is unregistered.
 * @param[in] configuration_data An optional pointer to the configuration data.
 * @param[in] configuration_data_size The size in bytes of configuration_data.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_OUT_OF_MEMORY Out of memory.
 * @retval OE_ALREADY_EXISTS A plugin for the same UUID is already registered.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_register_attester_plugin(
    oe_attester_t* plugin,
    const void* configuration_data,
    size_t configuration_data_size);

/**
 * oe_unregister_attester_plugin
 *
 * Unregisters an attester plugin.
 *
 * This is available in the enclave only.
 *
 * @experimental
 *
 * @param[in] plugin A pointer to the attestation plugin struct.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_NOT_FOUND The plugin does not exist or has not been registered.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_unregister_attester_plugin(oe_attester_t* plugin);

/**
 * oe_find_attester_plugin
 *
 * Find an attester plugin of specified format ID.
 *
 * This is available in the enclave only.
 *
 * @experimental
 *
 * @param[in] format_id Pointer to the evidence format ID requested.
 * @param[out] attester_plugin Pointer to a buffer to hold the found plugin.
 * The caller shall not modify or reclaim the returned plugin buffer.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_NOT_FOUND No plugin of the given format ID can be found.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_find_attester_plugin(
    const oe_uuid_t* format_id,
    oe_attester_t** attester_plugin);

#endif // OE_BUILD_ENCLAVE

/**
 * oe_register_verifier_plugin
 *
 * Registers a new verifier plugin and optionally configures it with plugin
 * specific configuration data. The function will fail if a plugin for the
 * same UUID has already been registered.
 *
 * This is available in the enclave and host.
 *
 * @experimental
 *
 * @param[in] plugin A pointer to the attestation plugin struct. Note that this
 * will not copy the contents of the plugin struct, so the struct must be kept
 * valid until the plugin is unregistered.
 * @param[in] configuration_data An optional pointer to the configuration data.
 * @param[in] configuration_data_size The size in bytes of configuration_data.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_OUT_OF_MEMORY Out of memory.
 * @retval OE_ALREADY_EXISTS A plugin for the same UUID is already registered.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_register_verifier_plugin(
    oe_verifier_t* plugin,
    const void* configuration_data,
    size_t configuration_data_size);

/**
 * oe_unregister_verifier_plugin
 *
 * Unregisters an verifier plugin.
 *
 * This is available in the enclave and host.
 *
 * @experimental
 *
 * @param[in] plugin A pointer to the attestation plugin struct.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_NOT_FOUND The plugin does not exist or has not been registered.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_unregister_verifier_plugin(oe_verifier_t* plugin);

/**
 * oe_find_verifier_plugin
 *
 * Find a verifier plugin of specified format ID.
 *
 * This is available in the enclave only.
 *
 * @experimental
 *
 * @param[in] format_id Pointer to the evidence format ID requested.
 * @param[out] verifier_plugin Pointer to a buffer to hold the found plugin.
 * The caller shall not modify or reclaim the returned plugin buffer.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_NOT_FOUND No plugin of the given format ID can be found.
 * @retval An appropriate error code on failure.
 */
oe_result_t oe_find_verifier_plugin(
    const oe_uuid_t* format_id,
    oe_verifier_t** verifier_plugin);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_PLUGIN_H */
