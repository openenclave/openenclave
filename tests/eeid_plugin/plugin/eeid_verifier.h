// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_VERIFIER_H
#define _OE_EEID_VERIFIER_H

#include <openenclave/attestation/plugin.h>

#include "eeid_plugin.h"

oe_result_t eeid_verify_evidence(
    oe_verifier_t* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length);

oe_result_t eeid_free_claims_list(
    oe_verifier_t* context,
    oe_claim_t* claims,
    size_t claims_length);

static oe_verifier_t eeid_verifier = {
    .base =
        {
            .format_id = {OE_EEID_PLUGIN_UUID},
            .on_register = &eeid_on_register,
            .on_unregister = &eeid_on_unregister,
        },
    .verify_evidence = &eeid_verify_evidence,
    .free_claims_list = &eeid_free_claims_list};

#endif // _OE_EEID_VERIFIER_H