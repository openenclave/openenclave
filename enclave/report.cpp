// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/calls.h>
#include <openenclave/bits/cmac.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/keys.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include <openenclave/types.h>

// This file is .cpp in order to use C++ static initialization.

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(SGX_ReportData));

static OE_Result _OE_GetReportKey(const SGX_Report* sgxReport, SGX_Key* sgxKey)
{
    OE_Result result = OE_UNEXPECTED;
    SGX_KeyRequest sgxKeyRequest = {0};

    sgxKeyRequest.key_name = SGX_KEYSELECT_REPORT;
    OE_Memcpy(sgxKeyRequest.key_id, sgxReport->keyid, sizeof(sgxReport->keyid));

    OE_CHECK(OE_GetKey(&sgxKeyRequest, sgxKey));
    result = OE_OK;

done:
    // Cleanup secret.
    OE_SecureZeroFill(&sgxKeyRequest, sizeof(sgxKeyRequest));

    return result;
}

// OE_VerifyReport needs crypto library's cmac computation. oecore does not have
// crypto functionality. Hence OE_Verify report is implemented here instead of
// in oecore. Also see ECall_HandleVerifyReport below.
OE_Result OE_VerifyReport(
    const uint8_t* report,
    uint32_t reportSize,
    OE_Report* parsedReport)
{
    OE_Result result = OE_UNEXPECTED;
    OE_Report oeReport = {0};
    SGX_Key sgxKey = {0};

    SGX_Report* sgxReport = NULL;

    const uint32_t aesCMACLength = sizeof(sgxKey);
    OE_AESCMAC reportAESCMAC = {{0}};
    OE_AESCMAC computedAESCMAC = {{0}};

    OE_CHECK(OE_ParseReport(report, reportSize, &oeReport));

    if (oeReport.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        OE_RAISE(OE_UNSUPPORTED);
    }
    else
    {
        sgxReport = (SGX_Report*)report;

        OE_CHECK(_OE_GetReportKey(sgxReport, &sgxKey));

        OE_CHECK(
            OE_AESCMACSign(
                (uint8_t*)&sgxKey,
                sizeof(sgxKey),
                (uint8_t*)&sgxReport->body,
                sizeof(sgxReport->body),
                &computedAESCMAC));

        // Fetch cmac from sgxReport.
        // Note: sizeof(sgxReport->mac) <= sizeof(OE_AESCMAC).
        OE_SecureMemcpy(&reportAESCMAC, sgxReport->mac, aesCMACLength);

        if (!OE_SecureAESCMACEqual(&computedAESCMAC, &reportAESCMAC))
            OE_RAISE(OE_VERIFY_FAILED);
    }

    // Optionally return parsed report.
    if (parsedReport != NULL)
        *parsedReport = oeReport;

    result = OE_OK;

done:
    // Cleanup secret.
    OE_SecureZeroFill(&sgxKey, sizeof(sgxKey));

    return result;
}

static OE_Result _SafeCopyVerifyReportArgs(
    uint64_t argIn,
    OE_VerifyReportArgs* safeArg,
    uint8_t* reportBuffer)
{
    OE_Result result = OE_UNEXPECTED;
    OE_VerifyReportArgs* unsafeArg = (OE_VerifyReportArgs*)argIn;

    if (!unsafeArg || !OE_IsOutsideEnclave(unsafeArg, sizeof(*unsafeArg)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy arg to prevent TOCTOU issues.
    OE_SecureMemcpy(safeArg, unsafeArg, sizeof(*safeArg));

    if (!safeArg->report ||
        !OE_IsOutsideEnclave(safeArg->report, safeArg->reportSize))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (safeArg->reportSize > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy report to prevent TOCTOU issues.
    OE_SecureMemcpy(reportBuffer, safeArg->report, safeArg->reportSize);
    safeArg->report = reportBuffer;

    result = OE_OK;

done:
    return result;
}

static OE_Result _SafeCopyVerifyReportArgsOuput(
    const OE_VerifyReportArgs* safeArg,
    uint64_t argIn)
{
    OE_Result result = OE_UNEXPECTED;
    OE_VerifyReportArgs* unsafeArg = (OE_VerifyReportArgs*)argIn;

    if (!unsafeArg || !OE_IsOutsideEnclave(unsafeArg, sizeof(*unsafeArg)))
        OE_RAISE(OE_INVALID_PARAMETER);

    unsafeArg->result = safeArg->result;
    result = safeArg->result;

done:
    return result;
}

// The report key is never sent out to the host. The host side OE_VerifyReport
// invokes OE_FUNC_VERIFY_REPORT ECall on the enclave. ECalls are handled in
// oecore; however oecore has no access to enclave's OE_VerifyReport (see
// above). Therefore, OE_VerifyReport is exposed to oecore as a registered
// ECall.
static void ECall_HandleVerifyReport(uint64_t argIn, uint64_t* argOut)
{
    OE_Result result = OE_UNEXPECTED;
    OE_VerifyReportArgs arg;
    uint8_t reportBuffer[OE_MAX_REPORT_SIZE];

    OE_CHECK(_SafeCopyVerifyReportArgs(argIn, &arg, reportBuffer));

    OE_CHECK(OE_VerifyReport(reportBuffer, arg.reportSize, NULL));

    // success.
    result = OE_OK;

done:
    arg.result = result;
    _SafeCopyVerifyReportArgsOuput(&arg, argIn);
}

// Use static initializer to register ECall_HandleVerifyReport.
static OE_Result g_InitECalls =
    OE_RegisterECall(OE_FUNC_VERIFY_REPORT, ECall_HandleVerifyReport);
