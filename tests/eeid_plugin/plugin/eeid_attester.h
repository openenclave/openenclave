// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_ATTESTER_H
#define _OE_EEID_ATTESTER_H

#include <openenclave/attestation/plugin.h>

#include "eeid_attester.h"
#include "eeid_plugin.h"

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

static oe_attester_t eeid_attester = {
    .base =
        {
            .format_id = {OE_EEID_PLUGIN_UUID},
            .on_register = &eeid_on_register,
            .on_unregister = &eeid_on_unregister,
        },
    .get_evidence = &eeid_get_evidence,
    .free_evidence = &eeid_free_evidence,
    .free_endorsements = &eeid_free_endorsements};

#endif // _OE_EEID_ATTESTER_H
