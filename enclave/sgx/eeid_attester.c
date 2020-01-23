
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/attestation/sgx/eeid_attester.h>
#include <openenclave/bits/eeid.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/eeid_plugin.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/trace.h>

extern const void* __oe_get_eeid();

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/attestation/sgx/attester.h>
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

oe_result_t eeid_attester_on_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);

    oe_result_t result = OE_UNEXPECTED;

#ifdef OE_BUILD_ENCLAVE
    oe_attester_t* sgx_attest = oe_sgx_plugin_attester();
    result = oe_register_attester(sgx_attest, NULL, 0);
    if (result != OE_ALREADY_EXISTS)
        return result;
#else
    return OE_UNSUPPORTED;
#endif

    return result;
}

oe_result_t eeid_attester_on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    oe_result_t result = OE_UNEXPECTED;

#ifdef OE_BUILD_ENCLAVE
    oe_attester_t* sgx_attest = oe_sgx_plugin_attester();
    result = oe_unregister_attester(sgx_attest);
    if (result != OE_OK && result != OE_NOT_FOUND)
        return result;
#else
    return OE_UNSUPPORTED;
#endif

    return result;
}

oe_result_t eeid_get_evidence(
    oe_attester_t* context,
    uint32_t flags,
    const oe_claim_t* custom_claims,
    size_t custom_claims_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    OE_UNUSED(context);
    OE_UNUSED(flags);
    OE_UNUSED(custom_claims);
    OE_UNUSED(custom_claims_size);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);

    if (!evidence_buffer || !evidence_buffer_size)
        return OE_FAILURE;

    *evidence_buffer = NULL;
    *evidence_buffer_size = 0;

    if (endorsements_buffer)
        *endorsements_buffer = NULL;
    if (endorsements_buffer_size)
        *endorsements_buffer_size = 0;

#ifndef OE_BUILD_ENCLAVE
    return OE_UNSUPPORTED;
#else
    oe_result_t result = OE_UNEXPECTED;

    const oe_eeid_t* eeid = __oe_get_eeid();

    if (!eeid || eeid->data_size == 0)
        return OE_FAILURE;

    size_t eeid_sz = sizeof(oe_eeid_t) + eeid->data_size;

    oe_uuid_t sgx_uuid = {OE_SGX_PLUGIN_UUID};
    oe_claim_t* sgx_claims = NULL;
    size_t sgx_claims_size = 0;
    uint8_t* sgx_evidence_buffer = NULL;
    size_t sgx_evidence_buffer_size = 0;
    uint8_t* sgx_endorsements_buffer = NULL;
    size_t sgx_endorsements_buffer_size = 0;

    OE_CHECK(oe_get_evidence(
        &sgx_uuid,
        flags,
        sgx_claims,
        sgx_claims_size,
        opt_params,
        opt_params_size,
        &sgx_evidence_buffer,
        &sgx_evidence_buffer_size,
        &sgx_endorsements_buffer,
        &sgx_endorsements_buffer_size));

    *evidence_buffer_size = sizeof(eeid_evidence_t) + sgx_evidence_buffer_size +
                            sgx_endorsements_buffer_size + eeid_sz;
    *evidence_buffer = malloc(*evidence_buffer_size);
    if (!*evidence_buffer)
        return OE_OUT_OF_MEMORY;

    eeid_evidence_t* eeide = (eeid_evidence_t*)*evidence_buffer;
    eeide->evidence_sz = sgx_evidence_buffer_size;
    memcpy(eeide->data, sgx_evidence_buffer, sgx_evidence_buffer_size);
    eeide->endorsements_sz = sgx_endorsements_buffer_size;
    if (eeide->endorsements_sz != 0)
        memcpy(
            eeide->data + eeide->evidence_sz,
            sgx_endorsements_buffer,
            sgx_endorsements_buffer_size);
    eeide->eeid_sz = eeid_sz;
    memcpy(
        eeide->data + eeide->evidence_sz + eeide->endorsements_sz,
        eeid,
        eeid_sz);

    OE_CHECK(oe_free_evidence(sgx_evidence_buffer));
    OE_CHECK(oe_free_endorsements(sgx_endorsements_buffer));
    OE_CHECK(oe_free_claims_list(sgx_claims, sgx_claims_size));

    result = OE_OK;

done:
    return result;
#endif
}

oe_result_t eeid_free_evidence(oe_attester_t* context, uint8_t* evidence_buffer)
{
    OE_UNUSED(context);
    free(evidence_buffer);
    return OE_OK;
}

oe_result_t eeid_free_endorsements(
    oe_attester_t* context,
    uint8_t* endorsements_buffer)
{
    OE_UNUSED(context);
    free(endorsements_buffer);
    return OE_OK;
}