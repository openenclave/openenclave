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
    const sgx_report_t* sgxReport,
    sgx_key_t* sgxKey)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_key_request_t sgxKeyRequest = {0};

    sgxKeyRequest.key_name = SGX_KEYSELECT_REPORT;
    oe_memcpy(sgxKeyRequest.key_id, sgxReport->keyid, sizeof(sgxReport->keyid));

    OE_CHECK(oe_get_key(&sgxKeyRequest, sgxKey));
    result = OE_OK;

done:
    // Cleanup secret.
    oe_secure_zero_fill(&sgxKeyRequest, sizeof(sgxKeyRequest));

    return result;
}

// oe_verify_report needs crypto library's cmac computation. oecore does not
// have
// crypto functionality. Hence oe_verify report is implemented here instead of
// in oecore. Also see ECall_HandleVerifyReport below.
oe_result_t oe_verify_report(
    const uint8_t* report,
    uint32_t reportSize,
    oe_report_t* parsedReport)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oeReport = {0};
    sgx_key_t sgxKey = {0};

    sgx_report_t* sgxReport = NULL;

    const uint32_t aesCMACLength = sizeof(sgxKey);
    OE_AESCMAC reportAESCMAC = {{0}};
    OE_AESCMAC computedAESCMAC = {{0}};

    OE_CHECK(oe_parse_report(report, reportSize, &oeReport));

    if (oeReport.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        OE_CHECK(
            VerifyQuoteImpl(report, reportSize, NULL, 0, NULL, 0, NULL, 0));
    }
    else
    {
        sgxReport = (sgx_report_t*)report;

        OE_CHECK(_oe_get_report_key(sgxReport, &sgxKey));

        OE_CHECK(
            oe_aes_cmac_sign(
                (uint8_t*)&sgxKey,
                sizeof(sgxKey),
                (uint8_t*)&sgxReport->body,
                sizeof(sgxReport->body),
                &computedAESCMAC));

        // Fetch cmac from sgxReport.
        // Note: sizeof(sgxReport->mac) <= sizeof(OE_AESCMAC).
        oe_secure_memcpy(&reportAESCMAC, sgxReport->mac, aesCMACLength);

        if (!oe_secure_aes_cmac_equal(&computedAESCMAC, &reportAESCMAC))
            OE_RAISE(OE_VERIFY_FAILED);
    }

    // Optionally return parsed report.
    if (parsedReport != NULL)
        *parsedReport = oeReport;

    result = OE_OK;

done:
    // Cleanup secret.
    oe_secure_zero_fill(&sgxKey, sizeof(sgxKey));

    return result;
}

static oe_result_t _SafeCopyVerifyReportArgs(
    uint64_t argIn,
    oe_verify_report_args_t* safeArg,
    uint8_t* reportBuffer)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t* unsafeArg = (oe_verify_report_args_t*)argIn;

    if (!unsafeArg || !oe_is_outside_enclave(unsafeArg, sizeof(*unsafeArg)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy arg to prevent TOCTOU issues.
    oe_secure_memcpy(safeArg, unsafeArg, sizeof(*safeArg));

    if (!safeArg->report ||
        !oe_is_outside_enclave(safeArg->report, safeArg->reportSize))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (safeArg->reportSize > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy report to prevent TOCTOU issues.
    oe_secure_memcpy(reportBuffer, safeArg->report, safeArg->reportSize);
    safeArg->report = reportBuffer;

    result = OE_OK;

done:
    return result;
}

static oe_result_t _SafeCopyVerifyReportArgsOuput(
    const oe_verify_report_args_t* safeArg,
    uint64_t argIn)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t* unsafeArg = (oe_verify_report_args_t*)argIn;

    if (!unsafeArg || !oe_is_outside_enclave(unsafeArg, sizeof(*unsafeArg)))
        OE_RAISE(OE_INVALID_PARAMETER);

    unsafeArg->result = safeArg->result;
    result = safeArg->result;

done:
    return result;
}

// The report key is never sent out to the host. The host side oe_verify_report
// invokes OE_FUNC_VERIFY_REPORT ECall on the enclave. ECalls are handled in
// oecore; however oecore has no access to enclave's oe_verify_report (see
// above). Therefore, oe_verify_report is exposed to oecore as a registered
// ECall.
static void _HandleVerifyReport(uint64_t argIn, uint64_t* argOut)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t arg;
    uint8_t reportBuffer[OE_MAX_REPORT_SIZE];

    OE_CHECK(_SafeCopyVerifyReportArgs(argIn, &arg, reportBuffer));

    OE_CHECK(oe_verify_report(reportBuffer, arg.reportSize, NULL));

    // success.
    result = OE_OK;

done:
    arg.result = result;
    _SafeCopyVerifyReportArgsOuput(&arg, argIn);
}

/* __liboeenclave_init() calls this function */
void oe_register_verify_report(void)
{
    oe_register_ecall(OE_FUNC_VERIFY_REPORT, _HandleVerifyReport);
}
