// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/report.c"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/raise.h>
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
    OE_Result result = OE_OK;
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
    arg->reportBufferSize = reportBufferSize;

    OE_CHECK(OE_ECall(enclave, OE_FUNC_GET_REPORT, (uint64_t)arg, NULL));
    result = arg->result;

done:
    if (arg)
    {
        memset(arg, 0, sizeof(*arg));
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
    OE_Result result = OE_OK;
    SGX_TargetInfo* sgxTargetInfo = NULL;
    SGX_Report* sgxReport = NULL;
    uint32_t sgxReportSize = sizeof(SGX_Report);
    OE_Report parsedReport;

    // reportData is a validated by _OE_GetLocalReport.

    // For remote attestation, the Quoting Enclave's target info is used.
    // optParams must not be supplied.
    if (optParams != NULL || optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportBuffer == NULL)
        OE_RAISE(OE_BUFFER_TOO_SMALL);

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

done:

    if (sgxTargetInfo)
    {
        memset(sgxTargetInfo, 0, sizeof(*sgxTargetInfo));
        free(sgxTargetInfo);
    }

    if (sgxReport)
    {
        memset(sgxReport, 0, sizeof(*sgxReport));
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
