// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include <openenclave/types.h>
#include "../common/report.c"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(SGX_ReportData));

static OE_Result _SGX_CreateReport(
    const void* reportData,
    uint32_t reportDataSize,
    const void* targetInfo,
    uint32_t targetInfoSize,
    SGX_Report* report)
{
    OE_Result result = OE_UNEXPECTED;

    // Allocate aligned objects as required by EREPORT instruction.
    SGX_TargetInfo ti OE_ALIGNED(512) = {0};
    SGX_ReportData rd OE_ALIGNED(128) = {0};
    SGX_Report r OE_ALIGNED(512) = {0};

    /*
     * Reject invalid parameters (reportData may be null).
     * If targetInfo is null, SGX returns the report for the enclave itself.
     */
    if (!report)
        OE_THROW(OE_INVALID_PARAMETER);

    if (targetInfoSize > sizeof(SGX_TargetInfo) ||
        reportDataSize > sizeof(SGX_ReportData))
        OE_THROW(OE_INVALID_PARAMETER);

    if (targetInfo != NULL)
        OE_Memcpy(&ti, targetInfo, targetInfoSize);

    if (reportData != NULL)
        OE_Memcpy(&rd, reportData, reportDataSize);

    OE_Memset(&r, 0, sizeof(SGX_Report));

    /* Invoke EREPORT instruction */
    asm volatile(
        "ENCLU"
        :
        : "a"(ENCLU_EREPORT), "b"(&ti), "c"(&rd), "d"(&r)
        : "memory");

    /* Copy REPORT to caller's buffer */
    OE_Memcpy(report, &r, sizeof(SGX_Report));

    result = OE_OK;

OE_CATCH:

    return result;
}

static OE_Result _OE_GetSGXReport(
    const void* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    void* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_OK;

    if (reportDataSize > OE_REPORT_DATA_SIZE)
        OE_THROW(OE_INVALID_PARAMETER);

    // optParams may be null, in which case SGX returns the report for the
    // enclave itself.
    if (optParams == NULL && optParamsSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    // If supplied, it must be a valid SGX_TargetInfo.
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

    OE_TRY(
        _SGX_CreateReport(
            reportData,
            reportDataSize,
            optParams,
            optParamsSize,
            reportBuffer));

    *reportBufferSize = sizeof(SGX_Report);

OE_CATCH:

    return result;
}

static OE_Result _OE_GetSGXTargetInfo(SGX_TargetInfo* targetInfo)
{
    OE_Result result = OE_OK;
    OE_GetQETargetInfoArgs* args =
        (OE_GetQETargetInfoArgs*)OE_HostCalloc(1, sizeof(*args));
    if (args == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    if (OE_OCall(
            OE_FUNC_GET_QE_TARGET_INFO,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        OE_THROW(OE_INVALID_TARGET_INFO);

    result = args->result;
    if (result == OE_OK)
        *targetInfo = args->targetInfo;

OE_CATCH:
    if (args)
    {
        OE_Memset(args, 0, sizeof(*args));
        OE_HostFree(args);
    }

    return result;
}

static OE_Result _OE_GetQuote(
    const SGX_Report* sgxReport,
    uint8_t* quote,
    uint32_t* quoteSize)
{
    OE_Result result = OE_OK;
    uint32_t argSize = sizeof(OE_GetQETargetInfoArgs);

    // If quote buffer is NULL, then ignore passed in quoteSize value.
    // This treats scenarios where quote == NULL and *quoteSizee == large-value as OE_BUFFER_TOO_SMALL.
    if (quote == NULL)
        *quoteSize = 0;

    // Allocate memory for args structure + quote buffer.
    argSize += *quoteSize;

    OE_GetQuoteArgs* args = (OE_GetQuoteArgs*)OE_HostCalloc(1, argSize);
    args->sgxReport = *sgxReport;
    args->quoteSize = *quoteSize;

    if (args == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    OE_TRY(
        OE_OCall(
            OE_FUNC_GET_QUOTE,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));
    result = args->result;

    if (result == OE_OK || result == OE_BUFFER_TOO_SMALL)
        *quoteSize = args->quoteSize;

    if (result == OE_OK)
        OE_Memcpy(quote, args->quote, *quoteSize);

OE_CATCH:
    if (args)
    {
        OE_Memset(args, 0, argSize);
        OE_HostFree(args);
    }

    return result;
}

OE_Result _OE_GetRemoteReport(
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_OK;
    SGX_TargetInfo sgxTargetInfo = {0};
    SGX_Report sgxReport = {0};
    uint32_t sgxReportSize = sizeof(sgxReport);
    OE_Report parsedReport;

    // For remote attestation, the Quoting Enclave's target info is used.
    // optParams must not be supplied.
    if (optParams != NULL || optParamsSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /*
     * OCall: Get target info from Quoting Enclave.
     * This involves a call to host. The returned targetinfo is trusted.
     */
    OE_TRY(_OE_GetSGXTargetInfo(&sgxTargetInfo));

    /*
     * Get enclave's local report passing in the quoting enclave's target info.
     */
    OE_TRY(
        _OE_GetSGXReport(
            reportData,
            reportDataSize,
            &sgxTargetInfo,
            sizeof(sgxTargetInfo),
            &sgxReport,
            &sgxReportSize));

    /*
     * OCall: Get the quote for the local report.
     */
    OE_TRY(_OE_GetQuote(&sgxReport, reportBuffer, reportBufferSize));

    if (result == OE_OK)
    {
        if (OE_ParseReport(reportBuffer, *reportBufferSize, &parsedReport) !=
            OE_OK)
            OE_THROW(OE_INVALID_REPORT);

        if (!(parsedReport.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE))
            OE_THROW(OE_INVALID_REPORT);

        // Check if the report returned from host is trustable.
        if (reportData != NULL)
        {
            if (OE_Memcmp(
                    parsedReport.reportData, reportData, reportDataSize) != 0)
                OE_THROW(OE_INVALID_REPORT);
        }
    }

OE_CATCH:

    return result;
}

OE_Result OE_GetReport(
    uint32_t options,
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    if (options & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
    {
        return _OE_GetRemoteReport(
            reportData,
            reportDataSize,
            optParams,
            optParamsSize,
            reportBuffer,
            reportBufferSize);
    }

    // If no options are specified, default to locally attestable report.
    return _OE_GetSGXReport(
        reportData,
        reportDataSize,
        optParams,
        optParamsSize,
        reportBuffer,
        reportBufferSize);
}

OE_Result _HandleGetReport(uint64_t argIn)
{
    OE_GetReportArgs* argFromHost = (OE_GetReportArgs*)argIn;
    OE_GetReportArgs arg;

    if (!argFromHost || !OE_IsOutsideEnclave(argFromHost, sizeof(*argFromHost)))
        return OE_INVALID_PARAMETER;

    // Copy arg to prevent TOCTOU issues.
    // All input fields now lie in enclave memory.
    arg = *argFromHost;

    argFromHost->result = OE_GetReport(
        arg.options,
        (arg.reportDataSize != 0) ? arg.reportData : NULL,
        arg.reportDataSize,
        (arg.optParamsSize != 0) ? arg.optParams : NULL,
        arg.optParamsSize,
        arg.reportBuffer,
        arg.reportBufferSize);

    return OE_OK;
}
