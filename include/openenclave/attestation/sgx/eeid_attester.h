// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_ATTESTER_H
#define _OE_EEID_ATTESTER_H

#include <openenclave/internal/sgx/eeid_plugin.h>

oe_result_t eeid_get_evidence(
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

oe_result_t eeid_free_evidence(
    oe_attester_t* context,
    uint8_t* evidence_buffer);

oe_result_t eeid_free_endorsements(
    oe_attester_t* context,
    uint8_t* endorsements_buffer);

oe_result_t eeid_attester_on_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size);

oe_result_t eeid_attester_on_unregister(oe_attestation_role_t* context);

static oe_attester_t eeid_attester = {
    .base =
        {
            .format_id = {OE_EEID_PLUGIN_UUID},
            .on_register = &eeid_attester_on_register,
            .on_unregister = &eeid_attester_on_unregister,
        },
    .get_evidence = &eeid_get_evidence,
    .free_evidence = &eeid_free_evidence,
    .free_endorsements = &eeid_free_endorsements};

#endif // _OE_EEID_ATTESTER_H
