// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides a dummy implementation of an attester plugin and a
// verifier plugin in order to test the OE plugin management runtime
// implementation. It essentially tests that plugins are being registered
// correctly and can get/verify evidence based of the right UUID.

#ifndef _OE_MOCK_ATTESTER_H
#define _OE_MOCK_ATTESTER_H

#include <openenclave/internal/plugin.h>
#include <string.h>

#define MOCK_EVIDENCE "123"
#define MOCK_ENDORSEMENTS "456"

#define OE_MOCK_ATTESTER_UUID1                                            \
    {                                                                     \
        0x17, 0x04, 0x94, 0xa6, 0xab, 0x23, 0x47, 0x98, 0x8c, 0x38, 0x35, \
            0x1c, 0xb0, 0xb6, 0xaf, 0x09                                  \
    }

#define OE_MOCK_ATTESTER_UUID2                                            \
    {                                                                     \
        0x15, 0x6a, 0x29, 0x71, 0x27, 0xee, 0x41, 0xf1, 0x9b, 0x90, 0xff, \
            0xc7, 0xc6, 0x52, 0x68, 0xf1                                  \
    }

static inline oe_result_t mock_attester_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);
    return OE_OK;
}

static inline oe_result_t mock_attester_unregister(
    oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    return OE_OK;
}

#ifdef OE_BUILD_ENCLAVE

static inline oe_result_t mock_get_evidence(
    oe_attester_t* context,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    OE_UNUSED(context);
    OE_UNUSED(custom_claims);
    OE_UNUSED(custom_claims_length);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    *evidence_buffer = (uint8_t*)MOCK_EVIDENCE;
    *evidence_buffer_size = sizeof(MOCK_EVIDENCE);
    if (endorsements_buffer)
    {
        *endorsements_buffer = (uint8_t*)MOCK_ENDORSEMENTS;
        *endorsements_buffer_size = sizeof(MOCK_ENDORSEMENTS);
    }
    return OE_OK;
}

static inline oe_result_t mock_free_evidence(
    oe_attester_t* context,
    uint8_t* evidence_buffer)
{
    OE_UNUSED(context);
    OE_UNUSED(evidence_buffer);
    return OE_OK;
}

static inline oe_result_t mock_free_endorsements(
    oe_attester_t* context,
    uint8_t* endorsements_buffer)
{
    OE_UNUSED(context);
    OE_UNUSED(endorsements_buffer);
    return OE_OK;
}

#endif

static inline oe_result_t mock_verify_evidence(
    oe_verifier_t* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
{
    OE_UNUSED(context);
    OE_UNUSED(policies);
    OE_UNUSED(policies_size);

    if (evidence_buffer_size != sizeof(MOCK_EVIDENCE))
        return OE_VERIFY_FAILED;

    if (strcmp(MOCK_EVIDENCE, (const char*)evidence_buffer) != 0)
        return OE_VERIFY_FAILED;

    if (endorsements_buffer)
    {
        if (endorsements_buffer_size != sizeof(MOCK_ENDORSEMENTS))
            return OE_VERIFY_FAILED;

        if (strcmp(MOCK_ENDORSEMENTS, (const char*)endorsements_buffer) != 0)
            return OE_VERIFY_FAILED;
    }

    *claims =
        (oe_claim_t*)malloc(OE_REQUIRED_CLAIMS_COUNT * sizeof(oe_claim_t));
    if (*claims == NULL)
        return OE_OUT_OF_MEMORY;

    for (int i = 0; i < OE_REQUIRED_CLAIMS_COUNT; i++)
    {
        (*claims)[i].name = (char*)(OE_REQUIRED_CLAIMS[i]);
        if (strcmp(OE_REQUIRED_CLAIMS[i], OE_CLAIM_FORMAT_UUID) == 0)
        {
            (*claims)[i].value = (uint8_t*)&context->base.format_id;
            (*claims)[i].value_size = sizeof(oe_uuid_t);
        }
    }
    *claims_length = OE_REQUIRED_CLAIMS_COUNT;

    return OE_OK;
}

static inline oe_result_t mock_verify_evidence_bad(
    oe_verifier_t* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
{
    OE_UNUSED(context);
    OE_UNUSED(evidence_buffer);
    OE_UNUSED(evidence_buffer_size);
    OE_UNUSED(endorsements_buffer);
    OE_UNUSED(endorsements_buffer_size);
    OE_UNUSED(policies);
    OE_UNUSED(policies_size);

    *claims = (oe_claim_t*)malloc(
        (OE_REQUIRED_CLAIMS_COUNT - 1) * sizeof(oe_claim_t));
    if (*claims == NULL)
        return OE_OUT_OF_MEMORY;

    for (int i = 0; i < OE_REQUIRED_CLAIMS_COUNT - 1; i++)
    {
        (*claims)[i].name = (char*)(OE_REQUIRED_CLAIMS[i]);
        if (strcmp(OE_REQUIRED_CLAIMS[i], OE_CLAIM_FORMAT_UUID) == 0)
        {
            (*claims)[i].value = (uint8_t*)&context->base.format_id;
            (*claims)[i].value_size = sizeof(oe_uuid_t);
        }
    }
    *claims_length = OE_REQUIRED_CLAIMS_COUNT - 1;

    return OE_OK;
}

static inline oe_result_t mock_free_claims(
    oe_verifier_t* context,
    oe_claim_t* claims,
    size_t claims_length)
{
    OE_UNUSED(context);
    OE_UNUSED(claims_length);
    free(claims);
    return OE_OK;
}

#ifdef OE_BUILD_ENCLAVE

static oe_attester_t mock_attester1 = {
    .base =
        {
            .format_id = {OE_MOCK_ATTESTER_UUID1},
            .on_register = &mock_attester_register,
            .on_unregister = &mock_attester_unregister,
        },
    .get_evidence = &mock_get_evidence,
    .free_evidence = &mock_free_evidence,
    .free_endorsements = &mock_free_endorsements};

#endif

static oe_verifier_t mock_verifier1 = {
    .base =
        {
            .format_id = {OE_MOCK_ATTESTER_UUID1},
            .on_register = &mock_attester_register,
            .on_unregister = &mock_attester_unregister,
        },
    .verify_evidence = &mock_verify_evidence,
    .free_claims = &mock_free_claims};

#ifdef OE_BUILD_ENCLAVE

// Same implementation but different UUID.
static oe_attester_t mock_attester2 = {
    .base =
        {
            .format_id = {OE_MOCK_ATTESTER_UUID2},
            .on_register = &mock_attester_register,
            .on_unregister = &mock_attester_unregister,
        },
    .get_evidence = &mock_get_evidence,
    .free_evidence = &mock_free_evidence,
    .free_endorsements = &mock_free_endorsements};

#endif // OE_BUILD_ENCLAVE

static oe_verifier_t mock_verifier2 = {
    .base =
        {
            .format_id = {OE_MOCK_ATTESTER_UUID2},
            .on_register = &mock_attester_register,
            .on_unregister = &mock_attester_unregister,
        },
    .verify_evidence = &mock_verify_evidence,
    .free_claims = &mock_free_claims};

#ifdef OE_BUILD_ENCLAVE

static oe_verifier_t bad_verifier = {
    .base =
        {
            .format_id = {OE_MOCK_ATTESTER_UUID1},
            .on_register = &mock_attester_register,
            .on_unregister = &mock_attester_unregister,
        },
    .verify_evidence = &mock_verify_evidence_bad,
    .free_claims = &mock_free_claims};

#endif // OE_BUILD_ENCLAVE

#endif /* _OE_MOCK_ATTESTER_H */
