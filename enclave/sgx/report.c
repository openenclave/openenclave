// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/crypto/cmac.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/sgxkeys.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>
#include "../common/sgx/quote.h"
#include "platform_t.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static const oe_uuid_t _local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};

static oe_result_t _get_report_key(
    const sgx_report_t* sgx_report,
    sgx_key_t* sgx_key)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_key_request_t sgx_key_request = {0};

    sgx_key_request.key_name = SGX_KEYSELECT_REPORT;
    OE_CHECK(oe_memcpy_s(
        sgx_key_request.key_id,
        sizeof(sgx_key_request.key_id),
        sgx_report->keyid,
        sizeof(sgx_report->keyid)));

    OE_CHECK(oe_get_key(&sgx_key_request, sgx_key));
    result = OE_OK;

done:
    // Cleanup secret.
    oe_secure_zero_fill(&sgx_key_request, sizeof(sgx_key_request));

    return result;
}

// oe_verify_report_internal needs crypto library's cmac computation.
// oecore does not have crypto functionality. Hence oe_verify_report_internal
// is implemented here instead of in oecore.
// Also see ECall_HandleVerifyReport below.
oe_result_t oe_verify_report_internal(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    sgx_key_t sgx_key = {{0}};
    oe_report_header_t* header = (oe_report_header_t*)report;

    sgx_report_t* sgx_report = NULL;

    const size_t aes_cmac_length = sizeof(sgx_key);
    oe_aes_cmac_t report_aes_cmac = {{0}};
    oe_aes_cmac_t computed_aes_cmac = {{0}};

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        OE_CHECK(oe_verify_sgx_quote(
            header->report, header->report_size, NULL, 0, NULL));
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        sgx_report = (sgx_report_t*)header->report;

        OE_CHECK(_get_report_key(sgx_report, &sgx_key));

        OE_CHECK(oe_aes_cmac_sign(
            (uint8_t*)&sgx_key,
            sizeof(sgx_key),
            (uint8_t*)&sgx_report->body,
            sizeof(sgx_report->body),
            &computed_aes_cmac));

        // Fetch cmac from sgx_report.
        // Note: sizeof(sgx_report->mac) <= sizeof(oe_aes_cmac_t).
        oe_secure_memcpy(&report_aes_cmac, sgx_report->mac, aes_cmac_length);

        if (!oe_secure_aes_cmac_equal(&computed_aes_cmac, &report_aes_cmac))
            OE_RAISE(OE_VERIFY_FAILED_AES_CMAC_MISMATCH);
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    // Optionally return parsed report.
    if (parsed_report != NULL)
        *parsed_report = oe_report;

    result = OE_OK;

done:
    // Cleanup secret.
    oe_secure_zero_fill(&sgx_key, sizeof(sgx_key));

    return result;
}

oe_result_t oe_verify_report_ecall(const void* report, size_t report_size)
{
    return oe_verify_report_internal(report, report_size, NULL);
}

// This is the enclave version of oe_get_report_v2().

oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_attester_t* attester = NULL;
    const oe_uuid_t* format_id = NULL;

    if (!report_buffer || !report_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!((!report_data && !report_data_size) ||
          (report_data && report_data_size)))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!((!opt_params && !opt_params_size) ||
          (opt_params && opt_params_size == sizeof(sgx_target_info_t))))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION)
        format_id = &_ecdsa_uuid;
    else
        format_id = &_local_uuid;

    OE_CHECK(oe_attester_initialize());

    OE_CHECK(oe_find_attester_plugin(format_id, &attester));

    OE_CHECK(attester->get_report(
        attester,
        flags,
        report_data,
        report_data_size,
        opt_params,
        opt_params_size,
        report_buffer,
        report_buffer_size));

    result = OE_OK;

done:
    return result;
}

void oe_free_report(uint8_t* report_buffer)
{
    oe_free(report_buffer);
}

oe_result_t oe_get_report_v2_ecall(
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* report = NULL;
    uint8_t* report_host = NULL;
    size_t report_size = 0;

    if (!report_buffer || !report_buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_get_report_v2(
        flags, NULL, 0, opt_params, opt_params_size, &report, &report_size));

    report_host = oe_host_malloc(report_size);
    if (!report_host)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_memcpy_s(report_host, report_size, report, report_size));

    *report_buffer = report_host;
    *report_buffer_size = report_size;
    report_host = NULL;

    result = OE_OK;

done:
    if (report)
        oe_free_report(report);
    if (report_host)
        oe_free(report_host);
    return result;
}

oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* header = (oe_report_header_t*)report;
    oe_verifier_t* verifier = NULL;
    const oe_uuid_t* format_id = NULL;

    if (!report || !report_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
        format_id = &_ecdsa_uuid;
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
        format_id = &_local_uuid;
    else
        OE_RAISE(OE_UNSUPPORTED);

    OE_CHECK(oe_verifier_initialize());

    OE_CHECK(oe_find_verifier_plugin(format_id, &verifier));

    OE_CHECK(
        verifier->verify_report(verifier, report, report_size, parsed_report));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_verify_local_report_ecall(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* header = (oe_report_header_t*)report;

    if (!report || !report_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    else if (header->report_type != OE_REPORT_TYPE_SGX_LOCAL)
        OE_RAISE(OE_UNSUPPORTED);

    OE_CHECK(oe_verify_report(report, report_size, parsed_report));

    result = OE_OK;

done:
    return result;
}
