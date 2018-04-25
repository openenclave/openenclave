// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/keys.h>
#include <openenclave/bits/mac.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include <openenclave/types.h>

// This file is .cpp in order to use C++ static initialization.

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(SGX_ReportData));

static OE_Result _OE_GetReportKey(const SGX_Report* sgxReport, SGX_Key* sgxKey)
{
    OE_Result result = OE_OK;
    SGX_KeyRequest sgxKeyRequest = {0};

    sgxKeyRequest.key_name = SGX_KEYSELECT_REPORT;
    OE_Memcpy(sgxKeyRequest.key_id, sgxReport->keyid, sizeof(sgxReport->keyid));

    OE_CHECK(OE_GetKey(&sgxKeyRequest, sgxKey));

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
    OE_Result result = OE_OK;
    OE_Report pReport = {0};
    SGX_Key sgxKey = {0};

    SGX_Report* sgxReport = NULL;
    OE_MAC mac = {0};

    OE_CHECK(OE_ParseReport(report, reportSize, &pReport));

    if (pReport.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        OE_RAISE(OE_UNSUPPORTED);
    }
    else
    {
        sgxReport = (SGX_Report*)report;

        OE_CHECK(_OE_GetReportKey(sgxReport, &sgxKey));

        OE_CHECK(
            OE_GetMAC(
                (uint8_t*)&sgxKey,
                sizeof(sgxKey),
                (uint8_t*)&sgxReport->body,
                sizeof(sgxReport->body),
                &mac));

        // Perform constant-time mac comparison.
        if (!OE_ConstantTimeMemEqual(sgxReport->mac, mac.bytes, sizeof(mac)))
            OE_RAISE(OE_VERIFY_FAILED);
    }

    // Optionally return parsed report.
    if (parsedReport != NULL)
        *parsedReport = pReport;

done:
    // Cleanup secret.
    OE_SecureZeroFill(&sgxKey, sizeof(sgxKey));

    return result;
}

// The report key is never sent out to the host. The host side OE_VerifyReport
// invokes OE_FUNC_VERIFY_REPORT ECall on the enclave. ECalls are handled in
// oecore; however oecore has no access to enclave's OE_VerifyReport (see
// above). Therefore, OE_VerifyReport is exposed to oecore as a registered
// ECall.
static void ECall_HandleVerifyReport(uint64_t argIn, uint64_t* argOut)
{
    OE_Result result = OE_OK;
    OE_VerifyReportArgs* argFromHost = (OE_VerifyReportArgs*)argIn;
    OE_VerifyReportArgs arg;
    uint8_t report[OE_MAX_REPORT_SIZE];

    if (!argFromHost || !OE_IsOutsideEnclave(argFromHost, sizeof(*argFromHost)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy arg to prevent TOCTOU issues.
    arg = *argFromHost;

    if (!arg.report || !OE_IsOutsideEnclave(arg.report, arg.reportSize))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (arg.reportSize > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!argFromHost || !OE_IsOutsideEnclave(argFromHost, sizeof(*argFromHost)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy report to prevent TOCTOU issues.
    OE_Memcpy(report, arg.report, arg.reportSize);

    OE_CHECK(OE_VerifyReport(report, arg.reportSize, NULL));

done:
    if (argFromHost)
        argFromHost->result = result;
}

// Use static initializer to register ECall_HandleVerifyReport.
static OE_Result g_InitECalls =
    OE_RegisterECall(OE_FUNC_VERIFY_REPORT, ECall_HandleVerifyReport);