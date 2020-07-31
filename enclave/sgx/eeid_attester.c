
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/enclave.h>

#include <openenclave/attestation/sgx/eeid_attester.h>
#include <openenclave/attestation/sgx/eeid_plugin.h>
#include <openenclave/bits/attestation.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/eeid.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/trace.h>

#include "../common/attest_plugin.h"
#include "../common/sgx/endorsements.h"

#include <openenclave/enclave.h>

extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;
extern volatile bool eeid_checked;

static oe_result_t _eeid_attester_on_register(
    oe_attestation_role_t* context,
    const void* config_data,
    size_t config_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(config_data);
    OE_UNUSED(config_data_size);
    return OE_OK;
}

static oe_result_t _eeid_attester_on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    return OE_OK;
}

static oe_result_t _get_sgx_evidence(
    uint32_t flags,
    const void* custom_claims,
    size_t custom_claims_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_SHA256 hash = {0};
    uint8_t* report = NULL;
    size_t report_size = 0;

    OE_CHECK(
        oe_sgx_hash_custom_claims(custom_claims, custom_claims_size, &hash));

    OE_CHECK(oe_get_report(
        flags,
        hash.buf,
        sizeof(hash.buf),
        opt_params,
        opt_params_size,
        &report,
        &report_size));

    *evidence_buffer_size = report_size + custom_claims_size;
    *evidence_buffer = oe_malloc(*evidence_buffer_size);
    if (!*evidence_buffer)
        OE_RAISE(OE_OUT_OF_MEMORY);
    memcpy(*evidence_buffer, report, report_size);
    memcpy(*evidence_buffer + report_size, custom_claims, custom_claims_size);

    if (endorsements_buffer && (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION))
    {
        oe_report_header_t* header = (oe_report_header_t*)report;
        OE_CHECK(oe_get_sgx_endorsements(
            header->report,
            header->report_size,
            endorsements_buffer,
            endorsements_buffer_size));
    }

    result = OE_OK;

done:

    free(report);

    return result;
}

static oe_result_t _eeid_get_evidence(
    oe_attester_t* context,
    const void* custom_claims,
    size_t custom_claims_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    uint32_t flags = 0;
    oe_result_t result = OE_UNEXPECTED;
    oe_eeid_evidence_t* evidence = NULL;
    uint8_t *sgx_evidence_buffer = NULL, *sgx_endorsements_buffer = NULL;
    size_t sgx_evidence_buffer_size = 0, sgx_endorsements_buffer_size = 0;
    uint8_t* sgx_custom_claims = NULL;
    size_t sgx_custom_claims_size = 0;
    const oe_eeid_t* eeid = oe_get_eeid();
    const volatile oe_enclave_initialization_data_t* initialization_data =
        oe_get_initialization_data();

    OE_UNUSED(context);
    if (!evidence_buffer || !evidence_buffer_size || !eeid || !eeid_checked)
        OE_RAISE(OE_FAILURE);

    // For EEID, the flag is always set for remote attestation
    flags = OE_REPORT_FLAGS_REMOTE_ATTESTATION;

    *evidence_buffer = NULL;
    *evidence_buffer_size = 0;

    if (endorsements_buffer)
        *endorsements_buffer = NULL;
    if (endorsements_buffer_size)
        *endorsements_buffer_size = 0;

    if (eeid->signature_size != sizeof(sgx_sigstruct_t))
        OE_RAISE(OE_FAILURE);

    size_t eeid_size = oe_eeid_byte_size(eeid);

    // Serialize custom claims, including EEID base image sizes
    sgx_custom_claims_size =
        custom_claims_size + sizeof(oe_enclave_size_settings_t);
    sgx_custom_claims = oe_malloc(sizeof(oe_claim_t) * sgx_custom_claims_size);
    if (!sgx_custom_claims)
        OE_RAISE(OE_OUT_OF_MEMORY);
    memcpy(sgx_custom_claims, custom_claims, custom_claims_size);
    uint8_t* sizes_pos = sgx_custom_claims + custom_claims_size;
    size_t buf_remaining = sgx_custom_claims_size - custom_claims_size;
    oe_enclave_size_settings_t* sizes =
        (oe_enclave_size_settings_t*)&oe_enclave_properties_sgx.header
            .size_settings;
    OE_CHECK(oe_enclave_size_settings_hton(sizes, &sizes_pos, &buf_remaining));

    // Get SGX evidence
    OE_CHECK(_get_sgx_evidence(
        flags,
        sgx_custom_claims,
        sgx_custom_claims_size,
        opt_params,
        opt_params_size,
        &sgx_evidence_buffer,
        &sgx_evidence_buffer_size,
        &sgx_endorsements_buffer,
        &sgx_endorsements_buffer_size));

    // Prepare EEID evidence, prefixed with an attestation header.
    *evidence_buffer_size = sizeof(oe_eeid_evidence_t) +
                            sgx_evidence_buffer_size +
                            sgx_endorsements_buffer_size + eeid_size;
    evidence = oe_malloc(*evidence_buffer_size);
    if (!evidence)
        OE_RAISE(OE_OUT_OF_MEMORY);

    evidence->sgx_evidence_size = sgx_evidence_buffer_size;
    evidence->sgx_endorsements_size = sgx_endorsements_buffer_size;
    evidence->eeid_size = eeid_size;

    if (sgx_evidence_buffer_size != 0)
        memcpy(evidence->data, sgx_evidence_buffer, sgx_evidence_buffer_size);

    if (evidence->sgx_endorsements_size != 0)
        memcpy(
            evidence->data + evidence->sgx_evidence_size,
            sgx_endorsements_buffer,
            sgx_endorsements_buffer_size);

    OE_CHECK(oe_eeid_hton(
        eeid,
        evidence->data + evidence->sgx_evidence_size +
            evidence->sgx_endorsements_size,
        eeid_size));

    // Write evidence. This can't be done in-place.
    *evidence_buffer = oe_malloc(*evidence_buffer_size);
    if (!*evidence_buffer)
        OE_RAISE(OE_OUT_OF_MEMORY);
    OE_CHECK(oe_eeid_evidence_hton(
        evidence, *evidence_buffer, *evidence_buffer_size));

    // Write endorsements
    if (endorsements_buffer && initialization_data &&
        initialization_data->data && initialization_data->size)
    {
        *endorsements_buffer_size = initialization_data->size;
        *endorsements_buffer = oe_malloc(initialization_data->size);
        if (!*endorsements_buffer)
            OE_RAISE(OE_OUT_OF_MEMORY);
        memcpy(
            *endorsements_buffer,
            initialization_data->data,
            initialization_data->size);
    }

    result = OE_OK;

done:

    oe_free(sgx_evidence_buffer);
    oe_free(sgx_endorsements_buffer);
    oe_free(sgx_custom_claims);
    oe_free(evidence);

    return result;
}

static oe_result_t _eeid_free_evidence(
    oe_attester_t* context,
    uint8_t* evidence_buffer)
{
    OE_UNUSED(context);
    oe_free(evidence_buffer);
    return OE_OK;
}

static oe_result_t _eeid_free_endorsements(
    oe_attester_t* context,
    uint8_t* endorsements_buffer)
{
    OE_UNUSED(context);
    oe_free(endorsements_buffer);
    return OE_OK;
}

static oe_attester_t _eeid_attester = {
    .base =
        {
            .format_id = {OE_FORMAT_UUID_SGX_EEID_ECDSA_P256},
            .on_register = &_eeid_attester_on_register,
            .on_unregister = &_eeid_attester_on_unregister,
        },
    .get_evidence = &_eeid_get_evidence,
    .free_evidence = &_eeid_free_evidence,
    .free_endorsements = &_eeid_free_endorsements};

oe_result_t oe_sgx_eeid_attester_initialize(void)
{
    return oe_register_attester_plugin(&_eeid_attester, NULL, 0);
}

oe_result_t oe_sgx_eeid_attester_shutdown(void)
{
    return oe_unregister_attester_plugin(&_eeid_attester);
}
