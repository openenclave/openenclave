// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/crypto/cmac.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxkeys.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>
#include "../common/sgx/quote.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

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

// oe_verify_report needs crypto library's cmac computation. oecore does not
// have crypto functionality. Hence oe_verify report is implemented here instead
// of in oecore. Also see ECall_HandleVerifyReport below.
oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    sgx_key_t sgx_key = {{0}};
    oe_evidence_header_t* header = (oe_evidence_header_t*)report;

    sgx_report_t* sgx_report = NULL;

    const size_t aes_cmac_length = sizeof(sgx_key);
    oe_aes_cmac_t report_aes_cmac = {{0}};
    oe_aes_cmac_t computed_aes_cmac = {{0}};

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (header->tee_evidence_type == OE_TEE_TYPE_SGX_REMOTE)
    {
        OE_CHECK(VerifyQuoteImpl(
            header->tee_evidence,
            header->tee_evidence_size,
            NULL,
            0,
            NULL,
            0,
            NULL,
            0));
    }
    else if (header->tee_evidence_type == OE_TEE_TYPE_SGX_LOCAL)
    {
        sgx_report = (sgx_report_t*)header->tee_evidence;

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
            OE_RAISE(OE_VERIFY_FAILED);
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

static oe_result_t _safe_copy_verify_report_args(
    uint64_t arg_in,
    oe_verify_report_args_t* safe_arg,
    uint8_t** buffer)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t* unsafe_arg = (oe_verify_report_args_t*)arg_in;

    if (!unsafe_arg ||
        !oe_is_outside_enclave(unsafe_arg, sizeof(*unsafe_arg)) || !buffer)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Always set output.
    *buffer = NULL;

    // Copy arg to prevent TOCTOU issues.
    oe_secure_memcpy(safe_arg, unsafe_arg, sizeof(*safe_arg));

    if (!safe_arg->report ||
        !oe_is_outside_enclave(safe_arg->report, safe_arg->report_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (safe_arg->report_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Caller is expected to free the allocated buffer.
    *buffer = calloc(1, safe_arg->report_size);
    if (*buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Copy report to prevent TOCTOU issues.
    oe_secure_memcpy(*buffer, safe_arg->report, safe_arg->report_size);
    safe_arg->report = *buffer;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _safe_copy_verify_report_args_ouput(
    const oe_verify_report_args_t* safe_arg,
    uint64_t arg_in)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t* unsafe_arg = (oe_verify_report_args_t*)arg_in;

    if (!unsafe_arg || !oe_is_outside_enclave(unsafe_arg, sizeof(*unsafe_arg)))
        OE_RAISE(OE_INVALID_PARAMETER);

    unsafe_arg->result = safe_arg->result;
    result = safe_arg->result;

done:
    return result;
}

// The report key is never sent out to the host. The host side oe_verify_report
// invokes OE_ECALL_VERIFY_REPORT ECALL in the enclave. This function is called
// from liboecore.
void oe_handle_verify_report(uint64_t arg_in, uint64_t* arg_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t arg;
    uint8_t* buffer = NULL;

    OE_UNUSED(arg_out);

    OE_CHECK(_safe_copy_verify_report_args(arg_in, &arg, &buffer));

    OE_CHECK(oe_verify_report(arg.report, arg.report_size, NULL));

    // success.
    result = OE_OK;
done:
    arg.result = result;
    _safe_copy_verify_report_args_ouput(&arg, arg_in);
    free(buffer);
}
