// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cmac.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/keys.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
#include "../common/quote.h"

#include <stdlib.h>

// This file is .cpp in order to use C++ static initialization.

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static oe_result_t _oe_get_report_key(
    const sgx_report_t* sgx_report,
    sgx_key_t* sgx_key)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_key_request_t sgx_key_request = {0};

    sgx_key_request.key_name = SGX_KEYSELECT_REPORT;
    oe_memcpy(sgx_key_request.key_id, sgx_report->keyid, sizeof(sgx_report->keyid));

    OE_CHECK(oe_get_key(&sgx_key_request, sgx_key));
    result = OE_OK;

done:
    // Cleanup secret.
    oe_secure_zero_fill(&sgx_key_request, sizeof(sgx_key_request));

    return result;
}

// oe_verify_report needs crypto library's cmac computation. oecore does not
// have
// crypto functionality. Hence oe_verify report is implemented here instead of
// in oecore. Also see ECall_HandleVerifyReport below.
oe_result_t oe_verify_report(
    const uint8_t* report,
    uint32_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    sgx_key_t sgx_key = {0};

    sgx_report_t* sgx_report = NULL;

    const uint32_t aes_cmac_length = sizeof(sgx_key);
    OE_AESCMAC report_aescmac = {{0}};
    OE_AESCMAC computed_aescmac = {{0}};

    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (oe_report.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        OE_CHECK(
            VerifyQuoteImpl(report, report_size, NULL, 0, NULL, 0, NULL, 0));
    }
    else
    {
        sgx_report = (sgx_report_t*)report;

        OE_CHECK(_oe_get_report_key(sgx_report, &sgx_key));

        OE_CHECK(
            oe_aes_cmac_sign(
                (uint8_t*)&sgx_key,
                sizeof(sgx_key),
                (uint8_t*)&sgx_report->body,
                sizeof(sgx_report->body),
                &computed_aescmac));

        // Fetch cmac from sgx_report.
        // Note: sizeof(sgx_report->mac) <= sizeof(OE_AESCMAC).
        oe_secure_memcpy(&report_aescmac, sgx_report->mac, aes_cmac_length);

        if (!oe_secure_aes_cmac_equal(&computed_aescmac, &report_aescmac))
            OE_RAISE(OE_VERIFY_FAILED);
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
    uint8_t* report_buffer)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t* unsafe_arg = (oe_verify_report_args_t*)arg_in;

    if (!unsafe_arg || !oe_is_outside_enclave(unsafe_arg, sizeof(*unsafe_arg)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy arg to prevent TOCTOU issues.
    oe_secure_memcpy(safe_arg, unsafe_arg, sizeof(*safe_arg));

    if (!safe_arg->report ||
        !oe_is_outside_enclave(safe_arg->report, safe_arg->report_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (safe_arg->report_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy report to prevent TOCTOU issues.
    oe_secure_memcpy(report_buffer, safe_arg->report, safe_arg->report_size);
    safe_arg->report = report_buffer;

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

static void ECall_HandleVerifyReport(uint64_t arg_in, uint64_t* arg_out);

// Use static initializer to register ECall_HandleVerifyReport.
static oe_result_t g_init_ecalls =
    oe_register_ecall(OE_FUNC_VERIFY_REPORT, ECall_HandleVerifyReport);

// The report key is never sent out to the host. The host side oe_verify_report
// invokes OE_FUNC_VERIFY_REPORT ECall on the enclave. ECalls are handled in
// oecore; however oecore has no access to enclave's oe_verify_report (see
// above). Therefore, oe_verify_report is exposed to oecore as a registered
// ECall.
static void ECall_HandleVerifyReport(uint64_t arg_in, uint64_t* arg_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t arg;
    uint8_t report_buffer[OE_MAX_REPORT_SIZE];

    OE_CHECK(_safe_copy_verify_report_args(arg_in, &arg, report_buffer));

    OE_CHECK(oe_verify_report(report_buffer, arg.report_size, NULL));

    // success.
    result = OE_OK;

    // Prevent 'defined but not used' warning.
    OE_UNUSED(g_init_ecalls);
done:
    arg.result = result;
    _safe_copy_verify_report_args_ouput(&arg, arg_in);
}
