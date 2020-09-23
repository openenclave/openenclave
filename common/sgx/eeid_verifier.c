
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
#include <openenclave/bits/attestation.h>
#include <openenclave/bits/eeid.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/internal/eeid.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/trace.h>

#include "../attest_plugin.h"
#include "../common.h"
#include "quote.h"

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

typedef struct _header
{
    uint32_t version;
    oe_uuid_t format_id;
    uint64_t data_size;
    uint8_t data[];
} header_t;

static oe_result_t _add_claim(
    oe_claim_t* claim,
    void* name,
    size_t name_size,
    void* value,
    size_t value_size)
{
    if (*((uint8_t*)name + name_size - 1) != '\0')
        return OE_CONSTRAINT_FAILED;

    claim->name = (char*)oe_malloc(name_size);
    if (claim->name == NULL)
        return OE_OUT_OF_MEMORY;
    memcpy(claim->name, name, name_size);

    claim->value = (uint8_t*)oe_malloc(value_size);
    if (claim->value == NULL)
    {
        oe_free(claim->name);
        claim->name = NULL;
        return OE_OUT_OF_MEMORY;
    }
    memcpy(claim->value, value, value_size);
    claim->value_size = value_size;

    return OE_OK;
}

static oe_result_t _add_claims(
    oe_verifier_t* context,
    const uint8_t* r_enclave_hash,
    const uint8_t* r_signer_id,
    uint16_t r_product_id,
    uint32_t r_security_version,
    uint64_t r_attributes,
    uint32_t r_id_version,
    const uint8_t* r_enclave_base_hash,
    oe_claim_t** claims_out,
    size_t* claims_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t claims_index = 0;
    oe_claim_t* claims = NULL;

    if (!claims_out || !claims_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    claims = (oe_claim_t*)oe_malloc(
        (OE_REQUIRED_CLAIMS_COUNT + 1) * sizeof(oe_claim_t));
    if (claims == NULL)
        return OE_OUT_OF_MEMORY;

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ID_VERSION,
        sizeof(OE_CLAIM_ID_VERSION),
        &r_id_version,
        sizeof(r_id_version)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SECURITY_VERSION,
        sizeof(OE_CLAIM_SECURITY_VERSION),
        &r_security_version,
        sizeof(r_security_version)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ATTRIBUTES,
        sizeof(OE_CLAIM_ATTRIBUTES),
        &r_attributes,
        sizeof(r_attributes)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_UNIQUE_ID,
        sizeof(OE_CLAIM_UNIQUE_ID),
        (void*)r_enclave_hash,
        OE_UNIQUE_ID_SIZE));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SIGNER_ID,
        sizeof(OE_CLAIM_SIGNER_ID),
        (void*)r_signer_id,
        OE_SIGNER_ID_SIZE));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_PRODUCT_ID,
        sizeof(OE_CLAIM_PRODUCT_ID),
        &r_product_id,
        OE_PRODUCT_ID_SIZE));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_FORMAT_UUID,
        sizeof(OE_CLAIM_FORMAT_UUID),
        &context->base.format_id,
        sizeof(oe_uuid_t)));

    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_EEID_BASE_ID,
        sizeof(OE_CLAIM_EEID_BASE_ID),
        (void*)r_enclave_base_hash,
        OE_UNIQUE_ID_SIZE));

    *claims_out = claims;
    *claims_size_out = 8;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _verify_sgx_report(
    const oe_verifier_t* context,
    const oe_policy_t* policies,
    size_t policies_size,
    const uint8_t* sgx_evidence_buffer,
    size_t sgx_evidence_buffer_size,
    const uint8_t* sgx_endorsements_buffer,
    size_t sgx_endorsements_buffer_size,
    oe_claim_t** sgx_claims,
    size_t* sgx_claims_length,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    const uint8_t* report_buffer = sgx_evidence_buffer;
    oe_datetime_t* time = NULL;
    oe_report_header_t* header = (oe_report_header_t*)report_buffer;
    oe_sgx_endorsements_t sgx_endorsements;
    size_t sgx_claims_size = 0;

    for (size_t i = 0; i < policies_size; i++)
    {
        if (policies[i].type == OE_POLICY_ENDORSEMENTS_TIME)
        {
            if (policies[i].policy_size != sizeof(*time))
                return OE_INVALID_PARAMETER;
            time = (oe_datetime_t*)policies[i].policy;
        }
    }

    OE_CHECK(oe_parse_sgx_endorsements(
        (oe_endorsements_t*)sgx_endorsements_buffer,
        sgx_endorsements_buffer_size,
        &sgx_endorsements));
    OE_CHECK(oe_verify_quote_with_sgx_endorsements(
        header->report, header->report_size, &sgx_endorsements, time));

    sgx_claims_size = sgx_evidence_buffer_size -
                      (header->report_size + sizeof(oe_report_header_t));
    *sgx_claims = NULL;

    OE_CHECK(oe_parse_report(
        sgx_evidence_buffer,
        sgx_evidence_buffer_size - sgx_claims_size,
        parsed_report));

    /* Extract SGX claims */
    oe_sgx_extract_claims(
        SGX_FORMAT_TYPE_REMOTE,
        &context->base.format_id,
        header->report,
        header->report_size,
        header->report + header->report_size,
        sgx_claims_size,
        &sgx_endorsements,
        sgx_claims,
        sgx_claims_length);

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
    oe_eeid_t *attester_eeid = NULL, *verifier_eeid = NULL;
    oe_eeid_evidence_t* evidence = NULL;

    if ((!endorsements_buffer && endorsements_buffer_size) ||
        (endorsements_buffer && !endorsements_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    evidence = oe_malloc(evidence_buffer_size);
    OE_CHECK(
        oe_eeid_evidence_ntoh(evidence_buffer, evidence_buffer_size, evidence));

    sgx_evidence_buffer_size = evidence->sgx_evidence_size;
    sgx_endorsements_buffer_size = evidence->sgx_endorsements_size;
    eeid_buffer_size = evidence->eeid_size;
    eeid_buffer = evidence->data + evidence->sgx_evidence_size +
                  evidence->sgx_endorsements_size;

    // Make sure buffers are aligned so they can be cast to structs. Note that
    // the SGX evidendence and endorsements buffers contain structs that have
    // not been corrected for endianness.
    if (sgx_evidence_buffer_size != 0)
    {
        if ((sgx_evidence_buffer =
                 oe_memalign(2 * sizeof(void*), sgx_evidence_buffer_size)) == 0)
            OE_RAISE(OE_OUT_OF_MEMORY);
        memcpy(sgx_evidence_buffer, evidence->data, sgx_evidence_buffer_size);
    }

    if (sgx_endorsements_buffer_size != 0)
    {
        if ((sgx_endorsements_buffer = oe_memalign(
                 2 * sizeof(void*), sgx_endorsements_buffer_size)) == 0)
            OE_RAISE(OE_OUT_OF_MEMORY);
        memcpy(
            sgx_endorsements_buffer,
            evidence->data + evidence->sgx_evidence_size,
            sgx_endorsements_buffer_size);
    }

    if (eeid_buffer_size != 0)
    {
        attester_eeid = oe_memalign(2 * sizeof(void*), eeid_buffer_size);
        if (!attester_eeid)
            OE_RAISE(OE_OUT_OF_MEMORY);
        OE_CHECK(oe_eeid_ntoh(eeid_buffer, eeid_buffer_size, attester_eeid));

        if (attester_eeid->version != OE_EEID_VERSION)
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    {
        /* Verify SGX report */
        oe_report_t parsed_report;
        oe_claim_t* sgx_claims = NULL;
        size_t sgx_claims_length = 0;
        OE_CHECK(_verify_sgx_report(
            context,
            policies,
            policies_size,
            sgx_evidence_buffer,
            sgx_evidence_buffer_size,
            sgx_endorsements_buffer,
            sgx_endorsements_buffer_size,
            &sgx_claims,
            &sgx_claims_length,
            &parsed_report));

        const uint8_t* r_enclave_hash = parsed_report.identity.unique_id;
        const uint8_t* r_signer_id = parsed_report.identity.signer_id;
        uint16_t r_product_id = *((uint16_t*)parsed_report.identity.product_id);
        uint32_t r_security_version = parsed_report.identity.security_version;
        uint64_t r_attributes = parsed_report.identity.attributes;
        uint32_t r_id_version = parsed_report.identity.id_version;

        oe_free_claims(sgx_claims, sgx_claims_length);

        /* EEID passed to the verifier */
        if (endorsements_buffer)
        {
            verifier_eeid =
                oe_memalign(2 * sizeof(void*), endorsements_buffer_size);
            if (!verifier_eeid)
                OE_RAISE(OE_OUT_OF_MEMORY);
            OE_CHECK(oe_eeid_ntoh(
                endorsements_buffer, endorsements_buffer_size, verifier_eeid));
        }

        /* Check that the enclave-reported EEID data matches the verifier's
         * expectation. */
        if (verifier_eeid &&
            (attester_eeid->data_size != verifier_eeid->data_size ||
             attester_eeid->signature_size != verifier_eeid->signature_size ||
             memcmp(
                 attester_eeid->data,
                 verifier_eeid->data,
                 verifier_eeid->data_size + verifier_eeid->signature_size) !=
                 0))
            OE_RAISE(OE_VERIFY_FAILED);

        /* Verify EEID */
        const uint8_t* r_enclave_base_hash;
        OE_CHECK(verify_eeid(
            r_enclave_hash,
            r_signer_id,
            r_product_id,
            r_security_version,
            r_attributes,
            &r_enclave_base_hash,
            attester_eeid));

        /* Produce claims */
        if (claims && claims_size)
            _add_claims(
                context,
                r_enclave_hash,
                r_signer_id,
                r_product_id,
                r_security_version,
                r_attributes,
                r_id_version,
                r_enclave_base_hash,
                claims,
                claims_size);
    }

    result = OE_OK;

done:

    oe_memalign_free(sgx_evidence_buffer);
    oe_memalign_free(sgx_endorsements_buffer);
    oe_memalign_free(attester_eeid);
    oe_memalign_free(verifier_eeid);
    oe_free(evidence);

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
    .free_claims = &sgx_attestation_plugin_free_claims_list};

oe_result_t oe_sgx_eeid_verifier_initialize(void)
{
    return oe_register_verifier_plugin(&_eeid_verifier, NULL, 0);
}

oe_result_t oe_sgx_eeid_verifier_shutdown(void)
{
    return oe_unregister_verifier_plugin(&_eeid_verifier);
}
