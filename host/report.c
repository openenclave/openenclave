// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/calls.h>
#include <openenclave/bits/trace.h>
#include <openenclave/host.h>
#include "quote.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(SGX_ReportData));

static OE_Result _OE_GetLocalReport(
    OE_Enclave* enclave,
    const void* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_OK;
    SGX_TargetInfo* sgxTargetInfo = NULL;
    SGX_ReportData* sgxReportData = NULL;
    OE_GetSGXReportArgs sgxReportArgs;

    if (reportDataSize > OE_REPORT_DATA_SIZE)
        OE_THROW(OE_INVALID_PARAMETER);

    // Optional params may be null, in which case SGX returns the report for the
    // enclave itself. If supplied, it must be a valid SGX_TargetInfo.
    if (optParams != NULL && optParamsSize != sizeof(SGX_TargetInfo))
        OE_THROW(OE_INVALID_PARAMETER);

    // An SGX_Report will be filled into the report buffer.
    if (reportBufferSize == NULL)
        OE_THROW(OE_INVALID_PARAMETER);

    // When supplied buffer is small, report the expected buffer size so that
    // the user can create correctly sized buffer and call OE_GetReport again.
    if (reportBuffer == NULL || *reportBufferSize < sizeof(SGX_Report))
    {
        *reportBufferSize = sizeof(SGX_Report);
        OE_THROW(OE_BUFFER_TOO_SMALL);
    }

    sgxTargetInfo = (SGX_TargetInfo*)calloc(1, sizeof(SGX_TargetInfo));

    if (sgxTargetInfo == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    if (optParams)
        memcpy(sgxTargetInfo, optParams, optParamsSize);

    /*
     * Get SGX_Report from enclave.
     */
    sgxReportData = (SGX_ReportData*)calloc(1, sizeof(SGX_ReportData));

    if (sgxReportData == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    // Report data is optional.
    if (reportData != NULL)
        memcpy(sgxReportData, reportData, reportDataSize);

    sgxReportArgs.targetInfo = sgxTargetInfo;
    sgxReportArgs.reportData = sgxReportData;
    sgxReportArgs.report = (SGX_Report*)reportBuffer;

    OE_TRY(
        OE_ECall(
            enclave, OE_FUNC_GET_SGX_REPORT, (uint64_t)&sgxReportArgs, NULL));

OE_CATCH:

    if (sgxTargetInfo)
    {
        memset(sgxTargetInfo, 0, sizeof(*sgxTargetInfo));
        free(sgxTargetInfo);
    }

    if (sgxReportData)
    {
        memset(sgxReportData, 0, sizeof(*sgxReportData));
        free(sgxReportData);
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
    void* sgxReport = NULL;
    uint32_t sgxReportSize = sizeof(SGX_Report);

    // reportData is a validated by _OE_GetLocalReport.

    // For remote attestation, the Quoting Enclave's target info is used.
    // optParams must not be supplied.
    if (optParams != NULL || optParamsSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /*
     * Get target info from Quoting Enclave.
     */
    sgxTargetInfo = calloc(1, sizeof(SGX_TargetInfo));

    if (sgxTargetInfo == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    OE_TRY(SGX_GetQETargetInfo(sgxTargetInfo));

    /*
     * Get SGX_Report from the enclave.
     */
    sgxReport = calloc(1, sizeof(SGX_Report));

    if (sgxReport == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    OE_TRY(
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
    OE_TRY(SGX_GetQuote(sgxReport, reportBuffer, reportBufferSize));

OE_CATCH:

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
