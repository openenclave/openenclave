// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/report.c"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>
#include "quote.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(SGX_ReportData));

static OE_Result _OE_GetLocalReport(
    OE_Enclave* enclave,
    const void* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    void* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_GetReportArgs* arg = NULL;

    /*
     * Perform basic parameters validation here on the host side. Thorough
     * validation will be done in the enclave side.
     */

    // reportData can either be NULL or it can be a stream of bytes with length
    // < OE_REPORT_DATA_SIZE. When reportData is NULL, the reportSize must be
    // zero.
    if (reportData == NULL && reportDataSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportDataSize > OE_REPORT_DATA_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // optParams, if specified, must be a SGX_TargetInfo. When optParams is
    // NULL, optParamsSize must be zero.
    if (optParams != NULL && optParamsSize != sizeof(SGX_TargetInfo))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (optParams == NULL && optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /*
     * Populate arg fields.
     */
    arg = calloc(1, sizeof(*arg));
    if (arg == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (reportData != NULL)
        memcpy(arg->reportData, reportData, reportDataSize);

    // Request local report.
    arg->options = 0;

    arg->reportDataSize = reportDataSize;

    if (optParams != NULL)
        memcpy(arg->optParams, optParams, optParamsSize);

    arg->optParamsSize = optParamsSize;

    arg->reportBuffer = reportBuffer;
    arg->reportBufferSize = reportBufferSize ? *reportBufferSize : 0;

    OE_CHECK(OE_ECall(enclave, OE_FUNC_GET_REPORT, (uint64_t)arg, NULL));
    result = arg->result;

    if (reportBufferSize)
        *reportBufferSize = arg->reportBufferSize;

done:
    if (arg)
    {
        OE_SecureZeroFill(arg, sizeof(*arg));
        free(arg);
    }

    return result;
}

static OE_Result _OE_GetRemoteReport(
    OE_Enclave* enclave,
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_UNEXPECTED;
    SGX_TargetInfo* sgxTargetInfo = NULL;
    SGX_Report* sgxReport = NULL;
    uint32_t sgxReportSize = sizeof(SGX_Report);
    OE_Report parsedReport;

    // reportData is a validated by _OE_GetLocalReport.

    // For remote attestation, the Quoting Enclave's target info is used.
    // optParams must not be supplied.
    if (optParams != NULL || optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportBufferSize == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportBuffer == NULL)
        *reportBufferSize = 0;

    /*
     * Get target info from Quoting Enclave.
     */
    sgxTargetInfo = calloc(1, sizeof(SGX_TargetInfo));

    if (sgxTargetInfo == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(SGX_GetQETargetInfo(sgxTargetInfo));

    /*
     * Get SGX_Report from the enclave.
     */
    sgxReport = (SGX_Report*)calloc(1, sizeof(SGX_Report));

    if (sgxReport == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        _OE_GetLocalReport(
            enclave,
            reportData,
            reportDataSize,
            sgxTargetInfo,
            sizeof(*sgxTargetInfo),
            sgxReport,
            &sgxReportSize));

    /*
     * Get quote from Quoting Enclave.
     */
    OE_CHECK(SGX_GetQuote(sgxReport, reportBuffer, reportBufferSize));

    /*
     * Check that the entire report body in the returned quote matches the local
     * report.
     */
    if (OE_ParseReport(reportBuffer, *reportBufferSize, &parsedReport) != OE_OK)
        OE_RAISE(OE_UNEXPECTED);

    if (memcmp(
            parsedReport.enclaveReport,
            &sgxReport->body,
            sizeof(sgxReport->body)) != 0)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;

done:

    if (sgxTargetInfo)
    {
        OE_SecureZeroFill(sgxTargetInfo, sizeof(*sgxTargetInfo));
        free(sgxTargetInfo);
    }

    if (sgxReport)
    {
        OE_SecureZeroFill(sgxReport, sizeof(*sgxReport));
        free(sgxReport);
    }

    return result;
}

OE_Result OE_GetReport(
    OE_Enclave* enclave,
    uint32_t options,
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    if (options & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
        return _OE_GetRemoteReport(
            enclave,
            reportData,
            reportDataSize,
            optParams,
            optParamsSize,
            reportBuffer,
            reportBufferSize);

    // If no options are specified, default to local report.
    return _OE_GetLocalReport(
        enclave,
        reportData,
        reportDataSize,
        optParams,
        optParamsSize,
        reportBuffer,
        reportBufferSize);
}

OE_Result OE_VerifyReport(
    OE_Enclave* enclave,
    const uint8_t* report,
    uint32_t reportSize,
    OE_Report* parsedReport)
{
    OE_Result result = OE_UNEXPECTED;
    OE_VerifyReportArgs arg = {0};

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportSize == 0 || reportSize > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    arg.report = (uint8_t*)report;
    arg.reportSize = reportSize;
    arg.result = OE_FAILURE;

    // Call enclave to verify the report. Do not ask the enclave to return a
    // parsed report since the parsed report will then contain pointers to
    // enclave memory. Instead, pass NULL as the optional parsedReport out
    // parameter and parse the report below if requested.
    OE_CHECK(OE_ECall(enclave, OE_FUNC_VERIFY_REPORT, (uint64_t)&arg, NULL));
    OE_CHECK(arg.result);

    // Optionally return parsed report.
    if (parsedReport != NULL)
        OE_CHECK(OE_ParseReport(report, reportSize, parsedReport));

    result = OE_OK;
done:

    return result;
}
