// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/internal/safecrt.h>

#include "../attest_plugin.h"
#include "../common.h"
#include "../tlsparser.h"

static const oe_uuid_t _uuid_sgx_local_attestation = {
    OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static const oe_uuid_t _uuid_sgx_ecdsa = {OE_FORMAT_UUID_SGX_ECDSA};

oe_result_t oe_parse_evidence_with_inittime_claims(
    uint8_t* evidence_with_inittime_claims,
    size_t evidence_with_inittime_claims_size,
    uint8_t** output_evidence_buffer,
    size_t* output_evidence_buffer_size,
    uint8_t** output_inittime_custom_claims_buffer,
    size_t* output_inittime_custom_claims_buffer_size,
    uint8_t** output_runtime_custom_claims_buffer,
    size_t* output_runtime_custom_claims_buffer_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    bool has_input_inittime_claims = false;
    uint8_t* inittime_claims = NULL;
    size_t inittime_claims_size = 0;
    bool has_input_runtime_claims = false;
    uint8_t* runtime_claims = NULL;
    size_t runtime_claims_size = 0;
    oe_attestation_header_t* header = NULL;
    oe_uuid_t* format_id = NULL;
    uint8_t* report = NULL;
    size_t report_size = 0;

    if (!evidence_with_inittime_claims || !evidence_with_inittime_claims_size ||
        !output_evidence_buffer || !output_evidence_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    *output_evidence_buffer = NULL;
    *output_evidence_buffer_size = 0;

    if (output_inittime_custom_claims_buffer &&
        output_inittime_custom_claims_buffer_size)
    {
        *output_inittime_custom_claims_buffer = NULL;
        *output_inittime_custom_claims_buffer_size = 0;
        has_input_inittime_claims = true;
    }

    if (output_runtime_custom_claims_buffer &&
        output_runtime_custom_claims_buffer_size)
    {
        *output_runtime_custom_claims_buffer = NULL;
        *output_runtime_custom_claims_buffer_size = 0;
        has_input_runtime_claims = true;
    }

    // Find the header version
    header = (oe_attestation_header_t*)evidence_with_inittime_claims;
    if (header->version != OE_ATTESTATION_HEADER_VERSION)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "Invalid attestation header version %d, expected %d",
            header->version,
            OE_ATTESTATION_HEADER_VERSION);

    OE_CHECK(oe_safe_add_sizet(
        sizeof(oe_attestation_header_t), header->data_size, &evidence_size));

    // Extract inittime custom claims
    if (has_input_inittime_claims &&
        (evidence_with_inittime_claims_size > evidence_size))
    {
        uint64_t inittime_claims_offset;
        OE_CHECK(oe_safe_sub_sizet(
            evidence_with_inittime_claims_size,
            evidence_size,
            &inittime_claims_size));
        inittime_claims = (uint8_t*)oe_malloc(inittime_claims_size);
        if (!inittime_claims)
            OE_RAISE(OE_OUT_OF_MEMORY);
        OE_CHECK(oe_safe_add_u64(
            (uint64_t)evidence_with_inittime_claims,
            (uint64_t)evidence_size,
            &inittime_claims_offset));
        OE_CHECK(oe_memcpy_s(
            inittime_claims,
            inittime_claims_size,
            (void*)inittime_claims_offset,
            inittime_claims_size));
    }

    // Unwrap the report from evidence
    report = (uint8_t*)header->data;
    format_id = &header->format_id;
    if (!memcmp(format_id, &_uuid_sgx_local_attestation, sizeof(oe_uuid_t)))
        report_size = sizeof(sgx_report_t);
    else if (!memcmp(format_id, &_uuid_sgx_ecdsa, sizeof(oe_uuid_t)))
        OE_CHECK(oe_safe_add_sizet(
            ((sgx_quote_t*)report)->signature_len,
            sizeof(sgx_quote_t),
            &report_size));
    else
        // Do not support legacy format and raw quote
        OE_RAISE(OE_REPORT_PARSE_ERROR);

    if (evidence_size < report_size)
        OE_RAISE(OE_INCORRECT_REPORT_SIZE);

    // Extract runtime custom claims
    if (has_input_runtime_claims && (evidence_size > report_size))
    {
        uint64_t runtime_claims_offset;
        OE_CHECK(oe_safe_sub_sizet(
            header->data_size, report_size, &runtime_claims_size));
        runtime_claims = (uint8_t*)oe_malloc(runtime_claims_size);
        if (!runtime_claims)
            OE_RAISE(OE_OUT_OF_MEMORY);
        OE_CHECK(oe_safe_add_u64(
            (uint64_t)report, (uint64_t)report_size, &runtime_claims_offset));
        OE_CHECK(oe_memcpy_s(
            runtime_claims,
            runtime_claims_size,
            (void*)runtime_claims_offset,
            runtime_claims_size));
    }

    evidence = (uint8_t*)oe_malloc(evidence_size);
    if (!evidence)
        OE_RAISE(OE_OUT_OF_MEMORY);
    OE_CHECK(oe_memcpy_s(
        evidence,
        evidence_size,
        (void*)evidence_with_inittime_claims,
        evidence_size));

    *output_evidence_buffer = evidence;
    *output_evidence_buffer_size = evidence_size;
    if (has_input_inittime_claims)
    {
        *output_inittime_custom_claims_buffer = inittime_claims;
        *output_inittime_custom_claims_buffer_size = inittime_claims_size;
    }
    if (has_input_runtime_claims)
    {
        *output_runtime_custom_claims_buffer = runtime_claims;
        *output_runtime_custom_claims_buffer_size = runtime_claims_size;
    }

    result = OE_OK;

done:
    if (result != OE_OK)
    {
        oe_free(evidence);
        oe_free(inittime_claims);
        oe_free(runtime_claims);
    }
    oe_free(evidence_with_inittime_claims);
    return result;
}
