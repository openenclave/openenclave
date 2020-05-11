
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/attestation/sgx/eeid_verifier.h>
#include <openenclave/attestation/sgx/verifier.h>
#include <openenclave/bits/eeid.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/trace.h>

static oe_result_t _eeid_verifier_on_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);

    oe_result_t result = OE_UNEXPECTED;

    oe_verifier_t* sgx_verify = oe_sgx_plugin_verifier();
    result = oe_register_verifier(sgx_verify, NULL, 0);
    return result == OE_ALREADY_EXISTS ? OE_OK : result;
}

static oe_result_t _eeid_verifier_on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    oe_result_t result = OE_UNEXPECTED;

    oe_verifier_t* sgx_verify = oe_sgx_plugin_verifier();
    result = oe_unregister_verifier(sgx_verify);
    if (result != OE_OK && result != OE_NOT_FOUND)
        return result;

    return OE_OK;
}

typedef struct _header
{
    uint32_t version;
    oe_uuid_t format_id;
    uint64_t data_size;
    uint8_t data[];
} header_t;

static oe_result_t _eeid_verify_evidence(
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

    oe_result_t result = OE_UNEXPECTED;

    if (!evidence_buffer || evidence_buffer_size == 0 || !endorsements_buffer ||
        endorsements_buffer_size == 0)
        return OE_INVALID_PARAMETER;

    eeid_evidence_t* eeide = (eeid_evidence_t*)evidence_buffer;
    oe_claim_t* sgx_claims = NULL;
    size_t sgx_claims_size = 0;
    uint8_t* sgx_evidence_buffer = eeide->data;
    size_t sgx_evidence_buffer_size = eeide->eeid_sz;
    uint8_t* sgx_endorsements_buffer =
        eeide->endorsements_sz ? eeide->data + eeide->evidence_sz : NULL;
    size_t sgx_endorsements_buffer_size = eeide->endorsements_sz;

    OE_CHECK(oe_verify_evidence(
        sgx_evidence_buffer,
        sgx_evidence_buffer_size,
        sgx_endorsements_buffer,
        sgx_endorsements_buffer_size,
        policies,
        policies_size,
        &sgx_claims,
        &sgx_claims_size));

    const uint8_t* r_mrenclave = NULL;
    const uint8_t* r_mrsigner = NULL;
    uint16_t r_product_id = 0;
    uint32_t r_security_version = 0;
    uint64_t r_attributes = 0;

    for (size_t i = 0; i < sgx_claims_size; i++)
    {
        if (strcmp(sgx_claims[i].name, "unique_id") == 0)
            r_mrenclave = sgx_claims[i].value;
        else if (strcmp(sgx_claims[i].name, "signer_id") == 0)
            r_mrsigner = sgx_claims[i].value;
        else if (strcmp(sgx_claims[i].name, "product_id") == 0)
            r_product_id = *sgx_claims[i].value;
        else if (strcmp(sgx_claims[i].name, "security_version") == 0)
            r_security_version = *sgx_claims[i].value;
        else if (strcmp(sgx_claims[i].name, "attributes") == 0)
            r_attributes = *sgx_claims[i].value;
    }

    const oe_eeid_t* aeeid = /* EEID from attester */
        (oe_eeid_t*)(eeide->data + eeide->evidence_sz + eeide->endorsements_sz);
    const oe_eeid_t* veeid =
        (oe_eeid_t*)endorsements_buffer; /* EEID from verifier */

    // Check that the enclave-reported EEID data matches the verifier's
    // expectation.
    if (veeid && (aeeid->data_size != veeid->data_size ||
                  memcmp(aeeid->data, veeid->data, veeid->data_size) != 0))
        return OE_VERIFY_FAILED;

    OE_CHECK(verify_eeid(
        r_mrenclave,
        r_mrsigner,
        r_product_id,
        r_security_version,
        r_attributes,
        aeeid));

    *claims =
        (oe_claim_t*)malloc(OE_REQUIRED_CLAIMS_COUNT * sizeof(oe_claim_t));
    if (*claims == NULL)
        return OE_OUT_OF_MEMORY;

    for (int i = 0; i < OE_REQUIRED_CLAIMS_COUNT; i++)
    {
        (*claims)[i].name = (char*)(OE_REQUIRED_CLAIMS[i]);
        if (strcmp(OE_REQUIRED_CLAIMS[i], OE_CLAIM_PLUGIN_UUID) == 0)
        {
            (*claims)[i].value = (uint8_t*)&context->base.format_id;
            (*claims)[i].value_size = sizeof(oe_uuid_t);
        }
        // Forward base-image claims?
    }
    *claims_length = OE_REQUIRED_CLAIMS_COUNT;

    OE_CHECK(oe_free_claims_list(sgx_claims, sgx_claims_size));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _eeid_free_claims_list(
    oe_verifier_t* context,
    oe_claim_t* claims,
    size_t claims_length)
{
    OE_UNUSED(context);
    OE_UNUSED(claims_length);
    free(claims);
    return OE_OK;
}

static oe_verifier_t _eeid_verifier = {
    .base =
        {
            .format_id = {OE_EEID_PLUGIN_UUID},
            .on_register = &_eeid_verifier_on_register,
            .on_unregister = &_eeid_verifier_on_unregister,
        },
    .verify_evidence = &_eeid_verify_evidence,
    .free_claims_list = &_eeid_free_claims_list};

oe_verifier_t* oe_eeid_plugin_verifier(void)
{
    return &_eeid_verifier;
}