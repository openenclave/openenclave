
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#define oe_memalign_free oe_free
#else
#include <openenclave/host.h>
#include "../../host/memalign.h"
#endif

#include <openenclave/attestation/sgx/eeid_plugin.h>
#include <openenclave/attestation/sgx/eeid_verifier.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/bits/attestation.h>
#include <openenclave/bits/eeid.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/internal/eeid.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/trace.h>

#include "../attest_plugin.h"
#include "../common.h"
#include "quote.h"

static const oe_uuid_t _sgx_uuid = {OE_FORMAT_UUID_LEGACY_REPORT_REMOTE};

static oe_result_t _eeid_verifier_on_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);
    return OE_OK;
}

static oe_result_t _eeid_verifier_on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    return OE_OK;
}

static oe_result_t _add_claims(
    oe_verifier_t* context,
    const oe_claim_t* sgx_claims,
    size_t sgx_claims_length,
    const uint8_t* r_enclave_base_hash,
    uint8_t* eeid_data,
    size_t eeid_data_size,
    oe_claim_t** claims_out,
    size_t* claims_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t claims_index = 0;
    oe_claim_t* claims = NULL;
    size_t num_claims = sgx_claims_length + 2;

    if (!claims_out || !claims_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (eeid_data && eeid_data_size)
        num_claims++;

    claims = (oe_claim_t*)oe_malloc(num_claims * sizeof(oe_claim_t));
    if (claims == NULL)
        return OE_OUT_OF_MEMORY;

    for (size_t i = 0; i < sgx_claims_length; i++)
    {
        const oe_claim_t* sgx_claim = &sgx_claims[i];
        if (strcmp(sgx_claim->name, OE_CLAIM_FORMAT_UUID) != 0)
        {
            OE_CHECK(oe_sgx_add_claim(
                &claims[claims_index++],
                sgx_claim->name,
                strlen(sgx_claim->name) + 1,
                sgx_claim->value,
                sgx_claim->value_size));
        }
    }

    OE_CHECK(oe_sgx_add_claim(
        &claims[claims_index++],
        OE_CLAIM_FORMAT_UUID,
        sizeof(OE_CLAIM_FORMAT_UUID),
        &context->base.format_id,
        sizeof(oe_uuid_t)));

    OE_CHECK(oe_sgx_add_claim(
        &claims[claims_index++],
        OE_CLAIM_EEID_BASE_ID,
        sizeof(OE_CLAIM_EEID_BASE_ID),
        (void*)r_enclave_base_hash,
        OE_UNIQUE_ID_SIZE));

    if (eeid_data && eeid_data_size)
    {
        OE_CHECK(oe_sgx_add_claim(
            &claims[claims_index++],
            OE_CLAIM_EEID_DATA,
            sizeof(OE_CLAIM_EEID_DATA),
            (void*)eeid_data,
            eeid_data_size));
    }

    *claims_out = claims;
    *claims_size_out = claims_index;

    result = OE_OK;
done:
    return result;
}

oe_result_t _verify_evidence(
    oe_verifier_t* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length);

static oe_result_t _get_relevant_base_claims(
    const oe_claim_t* claims,
    size_t claims_length,
    oe_eeid_relevant_base_claims_t* relevant_claims)
{
    oe_result_t result = OE_UNEXPECTED;

    for (size_t i = 0; i < claims_length; i++)
    {
        const oe_claim_t* claim = &claims[i];

        if (strcmp(claim->name, OE_CLAIM_UNIQUE_ID) == 0)
        {
            relevant_claims->enclave_hash = claim->value;
            relevant_claims->enclave_hash_size = claim->value_size;
        }
        else if (strcmp(claim->name, OE_CLAIM_SIGNER_ID) == 0)
        {
            relevant_claims->signer_id = claim->value;
            relevant_claims->signer_id_size = claim->value_size;
        }
        else if (strcmp(claim->name, OE_CLAIM_PRODUCT_ID) == 0)
        {
            if (claim->value_size != OE_PRODUCT_ID_SIZE)
                OE_RAISE(QE_QUOTE_ENCLAVE_IDENTITY_PRODUCTID_MISMATCH);
            relevant_claims->product_id =
                (uint16_t)(claim->value[1] << 8 | claim->value[0]);
        }
        else if (strcmp(claim->name, OE_CLAIM_SECURITY_VERSION) == 0)
        {
            if (claim->value_size != sizeof(uint32_t))
                OE_RAISE(OE_INVALID_ISVSVN);
            relevant_claims->security_version = *(uint32_t*)(claim->value);
        }
        else if (strcmp(claim->name, OE_CLAIM_ATTRIBUTES) == 0)
        {
            if (claim->value_size != sizeof(uint64_t))
                OE_RAISE(OE_INVALID_PARAMETER);
            relevant_claims->attributes = *(uint64_t*)(claim->value);
        }
        else if (strcmp(claim->name, OE_CLAIM_ID_VERSION) == 0)
        {
            if (claim->value_size != sizeof(uint32_t))
                OE_RAISE(OE_INVALID_PARAMETER);
            relevant_claims->id_version = *(uint32_t*)(claim->value);
        }
    }

    result = OE_OK;

done:

    return result;
}

static oe_result_t _align_buffer(
    const uint8_t* buffer,
    size_t buffer_size,
    uint8_t** aligned_buffer)
{
    oe_result_t result = OE_UNEXPECTED;

    if (buffer_size == 0)
    {
        *aligned_buffer = NULL;
        return OE_OK;
    }

    if ((*aligned_buffer = oe_memalign(2 * sizeof(void*), buffer_size)) == 0)
        OE_RAISE(OE_OUT_OF_MEMORY);
    OE_CHECK(oe_memcpy_s(*aligned_buffer, buffer_size, buffer, buffer_size));

    result = OE_OK;

done:

    return result;
}

static oe_result_t _eeid_verify_evidence(
    oe_verifier_t* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_size)
{
    OE_UNUSED(context);

    oe_result_t result = OE_UNEXPECTED;
    uint8_t *sgx_evidence_buffer = NULL, *sgx_endorsements_buffer = NULL,
            *eeid_buffer = NULL;
    size_t sgx_evidence_buffer_size = 0, sgx_endorsements_buffer_size = 0,
           eeid_buffer_size = 0;
    oe_eeid_t* attester_eeid = NULL;
    uint8_t* verifier_eeid_data = NULL;
    size_t verifier_eeid_data_size = 0;
    oe_eeid_evidence_t* evidence = NULL;
    oe_eeid_endorsements_t* endorsements = NULL;
    oe_claim_t* sgx_claims = NULL;
    size_t sgx_claims_length = 0;
    oe_eeid_relevant_base_claims_t relevant_claims;
    const uint8_t* enclave_base_hash = NULL;
    oe_verifier_t sgx_context; /* Only needed for format id */

    if ((!endorsements_buffer && endorsements_buffer_size) ||
        (endorsements_buffer && !endorsements_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    if ((evidence = oe_malloc(evidence_buffer_size)) == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);
    OE_CHECK(
        oe_eeid_evidence_ntoh(evidence_buffer, evidence_buffer_size, evidence));

    sgx_evidence_buffer_size = evidence->base_evidence_size;

    eeid_buffer_size = evidence->eeid_size;
    eeid_buffer = evidence->data + evidence->base_evidence_size;

    // Make sure buffers are aligned so they can be cast to structs. Note that
    // the SGX evidendence and endorsements buffers contain structs that have
    // not been corrected for endianness.
    OE_CHECK(_align_buffer(
        evidence->data, sgx_evidence_buffer_size, &sgx_evidence_buffer));

    if (endorsements_buffer)
    {
        if ((endorsements = oe_malloc(endorsements_buffer_size)) == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);
        OE_CHECK(oe_eeid_endorsements_ntoh(
            endorsements_buffer, endorsements_buffer_size, endorsements));

        sgx_endorsements_buffer_size = endorsements->sgx_endorsements_size;
        OE_CHECK(_align_buffer(
            endorsements->data,
            sgx_endorsements_buffer_size,
            &sgx_endorsements_buffer));

        /* EEID data passed to the verifier */
        verifier_eeid_data_size = endorsements->eeid_endorsements_size;
        OE_CHECK(_align_buffer(
            endorsements->data + endorsements->sgx_endorsements_size,
            verifier_eeid_data_size,
            &verifier_eeid_data));
    }

    if (eeid_buffer_size != 0)
    {
        if ((attester_eeid =
                 oe_memalign(2 * sizeof(void*), eeid_buffer_size)) == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);
        OE_CHECK(oe_eeid_ntoh(eeid_buffer, eeid_buffer_size, attester_eeid));
        if (attester_eeid->version != OE_EEID_VERSION)
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Verify SGX report */
    sgx_context.base.format_id = _sgx_uuid;
    OE_CHECK(oe_sgx_verify_evidence(
        &sgx_context,
        sgx_evidence_buffer,
        sgx_evidence_buffer_size,
        sgx_endorsements_buffer,
        sgx_endorsements_buffer_size,
        policies,
        policies_size,
        &sgx_claims,
        &sgx_claims_length));

    OE_CHECK(_get_relevant_base_claims(
        sgx_claims, sgx_claims_length, &relevant_claims));

    /* Check that the enclave-reported EEID data matches the verifier's
     * expectation. */
    if (verifier_eeid_data &&
        (attester_eeid->data_size != verifier_eeid_data_size ||
         memcmp(
             attester_eeid->data,
             verifier_eeid_data,
             verifier_eeid_data_size) != 0))
        OE_RAISE(OE_VERIFY_FAILED);

    /* Verify EEID */
    OE_CHECK(verify_eeid(&relevant_claims, &enclave_base_hash, attester_eeid));

    /* Produce claims */
    if (claims && claims_size)
        _add_claims(
            context,
            sgx_claims,
            sgx_claims_length,
            enclave_base_hash,
            attester_eeid->data,
            attester_eeid->data_size,
            claims,
            claims_size);

    result = OE_OK;

done:

    oe_sgx_free_claims_list(&sgx_context, sgx_claims, sgx_claims_length);
    oe_memalign_free(sgx_evidence_buffer);
    oe_memalign_free(sgx_endorsements_buffer);
    oe_memalign_free(attester_eeid);
    oe_memalign_free(verifier_eeid_data);
    oe_free(evidence);
    oe_free(endorsements);

    return result;
}

static oe_verifier_t _eeid_verifier = {
    .base =
        {
            .format_id = {OE_FORMAT_UUID_SGX_EEID_ECDSA_P256},
            .on_register = &_eeid_verifier_on_register,
            .on_unregister = &_eeid_verifier_on_unregister,
        },
    .verify_evidence = &_eeid_verify_evidence,
    .free_claims = &oe_sgx_free_claims_list};

oe_result_t oe_sgx_eeid_verifier_initialize(void)
{
    return oe_register_verifier_plugin(&_eeid_verifier, NULL, 0);
}

oe_result_t oe_sgx_eeid_verifier_shutdown(void)
{
    return oe_unregister_verifier_plugin(&_eeid_verifier);
}
