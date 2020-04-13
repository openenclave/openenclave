// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file attestation_plugin.h
 *
 * This file defines the programming interface for developing an
 * attestation plugin for supporting alternative evidence formats.
 *
 */

#ifndef _OE_ATTESTATION_PLUGIN_H
#define _OE_ATTESTATION_PLUGIN_H

#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Struct that defines the base structure of each attestation role plugin.
 * Each attestation role will have an UUID to indicate what evidence format
 * is supported and have functions for registering/unregistering the plugin.
 * Each attestation role will also define the require function for their
 * specific role (i.e. `get_evidence` for the attester and `verifiy_evidence`
 * for the verifier).
 */
typedef struct _oe_attestation_role oe_attestation_role_t;
struct _oe_attestation_role
{
    /**
     * The UUID for the attestation role.
     */
    oe_uuid_t format_id;

    /**
     * The function that gets executed when the attestation role is registered.
     *
     * @experimental
     *
     * @param[in] context A pointer to the attestation role struct.
     * @param[in] config_data An optional pointer to the configuration data.
     * @param[in] config_data_size The size in bytes of config_data.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*on_register)(
        oe_attestation_role_t* context,
        const void* config_data,
        size_t config_data_size);

    /**
     * The function that gets executed when the attestation role is
     * unregistered.
     *
     * @experimental
     *
     * @param[in] context A pointer to the attestation role struct.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*on_unregister)(oe_attestation_role_t* context);
};

/**
 * The attester attestion role. The attester is reponsible for generating the
 * attestation evidence and must implement the functions below.
 */
typedef struct _oe_attester oe_attester_t;
struct _oe_attester
{
    /**
     * The base attestation role containing the common functions for each role.
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
     * @param[in] flags Specifying default value (0) generates evidence for
     * local attestation. Specifying OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION
     * generates evidence for remote attestation.
     * @param[in] custom_claims The optional custom claims list.
     * @param[in] custom_claims_length The number of custom claims.
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
        uint32_t flags,
        const oe_claim_t* custom_claims,
        size_t custom_claims_length,
        const void* opt_params,
        size_t opt_params_size,
        uint8_t** evidence_buffer,
        size_t* evidence_buffer_size,
        uint8_t** endorsements_buffer,
        size_t* endorsements_buffer_size);

    /**
     * Frees the generated attestation evidence and endorsements.
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

/**
 * The verifier attestion role. The verifier is reponsible for verifying the
 * attestation evidence and must implement the functions below.
 */
typedef struct _oe_verifier oe_verifier_t;
struct _oe_verifier
{
    /**
     * The base attestation role containing the common functions for each role.
     */
    oe_attestation_role_t base;

    /**
     * Verifies the attestation evidence and returns the claims contained in
     * the evidence.
     *
     * Each plugin must return the following required claims:
     *  - id_version (uint32_t)
     *      - Version number. Must be 1.
     *  - security_version (uint32_t)
     *      - Security version of the enclave. (ISVN for SGX).
     * - attributes (uint64_t)
     *      - Attributes flags for the evidence:
     *          - OE_REPORT_ATTRIBUTES_DEBUG: The evidence is for a debug
     * enclave.
     *          - OE_REPORT_ATTRIBUTES_REMOTE: The evidence can be used for
     * remote attestation.
     * - unique_id (uint8_t[32])
     *      - The unique ID for the enclave (MRENCLAVE for SGX).
     * - signer_id (uint8_t[32])
     *      - The signer ID for the enclave (MRSIGNER for SGX).
     * - product_id (uint8_t[32])
     *      - The product ID for the enclave (ISVPRODID for SGX).
     * - validity_from (oe_datetime_t)
     *      - Overall datetime from which the evidence and endorsements are
     *        valid.
     * - validity_until (oe_datetime_t)
     *      - Overall datetime at which the evidence and endorsements expire.
     * - plugin_uuid (uint8_t[16])
     *      - The UUID of the plugin used to verify the evidence.
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
     * @param[out] claims The list of returned claims.
     * @param[out] claims_length The number of claims.
     * @retval OE_OK on success.
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
     * Frees the generated claims.
     *
     * @experimental
     *
     * @param[in] context A pointer to the verifier plugin struct.
     * @param[out] claims The list of returned claims.
     * @param[out] claims_length The number of claims.
     * @retval OE_OK on success.
     * @retval An appropriate error code on failure.
     */
    oe_result_t (*free_claims_list)(
        oe_verifier_t* context,
        oe_claim_t* claims,
        size_t claims_length);
};

/**
 * oe_register_attester
 *
 * Registers a new attester plugin and optionally configures it with plugin
 * specific configuration data. The function will fail if the plugin UUID has
 * already been registered.
 *
 * This is available in the enclave only.
 *
 * @experimental
 *
 * @param[in] plugin A pointer to the attestation plugin struct. Note that this
 * will not copy the contents of the pointer, so the pointer must be kept valid
 * until the plugin is unregistered.
 * @param[in] config_data An optional pointer to the configuration data.
 * @param[in] config_data_size The size in bytes of config_data.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMTER Atleast one of the parameters is invalid.
 * @retval OE_OUT_OF_MEMORY Out of memory.
 * @retval OE_ALREADY_EXISTS A plugin with the same UUID is already registered.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_register_attester(
    oe_attester_t* plugin,
    const void* config_data,
    size_t config_data_size);

/**
 * oe_register_verifier
 *
 * Registers a new verifier plugin and optionally configures it with plugin
 * specific configuration data. The function will fail if the plugin UUID has
 * already been registered.
 *
 * This is available in the enclave and host.
 *
 * @experimental
 *
 * @param[in] plugin A pointer to the attestation plugin struct. Note that this
 * will not copy the contents of the pointer, so the pointer must be kept valid
 * until the plugin is unregistered.
 * @param[in] config_data An optional pointer to the configuration data.
 * @param[in] config_data_size The size in bytes of config_data.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMTER Atleast one of the parameters is invalid.
 * @retval OE_OUT_OF_MEMORY Out of memory.
 * @retval OE_ALREADY_EXISTS A plugin with the same UUID is already registered.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_register_verifier(
    oe_verifier_t* plugin,
    const void* config_data,
    size_t config_data_size);

/**
 * oe_unregister_attester
 *
 * Unregisters an attester plugin. This is available in the enclave only.
 *
 * @experimental
 *
 * @param[in] plugin A pointer to the attestation plugin struct.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMTER Atleast one of the parameters is invalid.
 * @retval OE_NOT_FOUND The plugin does not exist or has not been registered.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_unregister_attester(oe_attester_t* plugin);

/**
 * oe_unregister_verifier
 *
 * Unregisters an verifier plugin. This is available in the enclave and host.
 *
 * @experimental
 *
 * @param[in] plugin A pointer to the attestation plugin struct.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMTER Atleast one of the parameters is invalid.
 * @retval OE_NOT_FOUND The plugin does not exist or has not been registered.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_unregister_verifier(oe_verifier_t* plugin);

/**
 * oe_get_evidence
 *
 * Generates the attestation evidence for the given UUID attestation format.
 * This function is only available in the enclave.
 *
 * @experimental
 *
 * @param[in] evidence_format_uuid The UUID of the plugin.
 * @param[in] flags Specifying default value (0) generates evidence for local
 * attestation. Specifying OE_EVIDENCE_FLAGS_REMOTE_ATTESTATION generates
 * evidence for remote attestation.
 * @param[in] custom_claims The optional custom claims list.
 * @param[in] custom_claims_length The number of custom claims.
 * @param[in] opt_params The optional plugin-specific input parameters.
 * @param[in] opt_params_size The size of opt_params in bytes.
 * @param[out] evidence_buffer An output pointer that will be assigned the
 * address of the evidence buffer.
 * @param[out] evidence_buffer_size A pointer that points to the size of the
 * evidence buffer in bytes.
 * @param[out] endorsements_buffer An output pointer that will be assigned the
 * address of the endorsements buffer.
 * @param[out] endorsements_buffer_size A pointer that points to the size of the
 * endorsements buffer in bytes.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMTER Atleast one of the parameters is invalid.
 * @retval OE_NOT_FOUND The plugin does not exist or has not been registered.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_get_evidence(
    const oe_uuid_t* evidence_format_uuid,
    uint32_t flags,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);

/**
 * oe_free_evidence
 *
 * Frees the attestation evidence. This function is only available in the
 * enclave.
 *
 * @experimental
 *
 * @param[in] evidence_buffer A pointer to the evidence buffer.
 * @retval OE_OK The function succeeded.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_free_evidence(uint8_t* evidence_buffer);

/**
 * oe_free_endorsements
 *
 * Frees the generated attestation endorsements. This function is only available
 * in the enclave.
 *
 * @experimental
 *
 * @param[in] endorsements_buffer A pointer to the endorsements buffer.
 * @retval OE_OK The function succeeded.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_free_endorsements(uint8_t* endorsements_buffer);

/**
 * oe_verify_evidence
 *
 * Verifies the attestation evidence and returns well known and custom claims.
 * This is available in the enclave and host.
 *
 * The following claims will be returned at the minimum:
 *
 *  - id_version (uint32_t)
 *      - Version number. Must be 1.
 *  - security_version (uint32_t)
 *      - Security version of the enclave. (ISVN for SGX).
 * - attributes (uint64_t)
 *      - Attributes flags for the evidence:
 *          - OE_REPORT_ATTRIBUTES_DEBUG: The evidence is for a debug enclave.
 *          - OE_REPORT_ATTRIBUTES_REMOTE: The evidence can be used for remote
 * attestation.
 * - unique_id (uint8_t[32])
 *      - The unique ID for the enclave (MRENCLAVE for SGX).
 * - signer_id (uint8_t[32])
 *      - The signer ID for the enclave (MRSIGNER for SGX).
 * - product_id (uint8_t[32])
 *      - The product ID for the enclave (ISVPRODID for SGX).
 * - validity_from (oe_datetime_t, optional)
 *      - Overall datetime from which the evidence and endorsements are valid.
 * - validity_until (oe_datetime_t, optional)
 *      - Overall datetime at which the evidence and endorsements expire.
 * - plugin_uuid (uint8_t[16])
 *      - The UUID of the plugin used to verify the evidence.
 *
 * @experimental
 *
 * @param[in] evidence_buffer The evidence buffer.
 * @param[in] evidence_buffer_size The size of evidence_buffer in bytes.
 * @param[in] endorsements_buffer The optional endorsements buffer.
 * @param[in] endorsements_buffer_size The size of endorsements_buffer in bytes.
 * @param[in] policies An optional list of policies to use.
 * @param[in] policies_size The size of the policy list.
 * @param[out] claims The list of claims.
 * @param[out] claims_length The length of the claims list.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMTER Atleast one of the parameters is invalid.
 * @retval OE_NOT_FOUND The plugin does not exist or has not been registered.
 * @retval OE_CONSTRAINT_FAILED The UUIDs of the evidence and endorsements
 * differ.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_verify_evidence(
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length);

/**
 * oe_free_claims_list
 *
 * Frees a claims list.
 *
 * @experimental
 *
 * @param[in] claims The list of claims.
 * @param[in] claims_length The length of the claims list.
 * @retval OE_OK The function succeeded.
 * @retval OE_NOT_FOUND The plugin that generated the claims does not exist or
 * has not been registered, so the claims can't be freed.
 * @retval Otherwise, returns the error code the plugin's function.
 */
oe_result_t oe_free_claims_list(oe_claim_t* claims, size_t claims_length);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_PLUGIN_H */
