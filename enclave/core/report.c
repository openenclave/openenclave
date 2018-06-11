// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
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
        OE_RAISE(OE_INVALID_PARAMETER);

    if (targetInfoSize > sizeof(SGX_TargetInfo) ||
        reportDataSize > sizeof(SGX_ReportData))
        OE_RAISE(OE_INVALID_PARAMETER);

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

done:

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
    OE_Result result = OE_UNEXPECTED;

    if (reportDataSize > OE_REPORT_DATA_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // optParams may be null, in which case SGX returns the report for the
    // enclave itself.
    if (optParams == NULL && optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // If supplied, it must be a valid SGX_TargetInfo.
    if (optParams != NULL && optParamsSize != sizeof(SGX_TargetInfo))
        OE_RAISE(OE_INVALID_PARAMETER);

    // An SGX_Report will be filled into the report buffer.
    if (reportBufferSize == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // When supplied buffer is small, report the expected buffer size so that
    // the user can create correctly sized buffer and call OE_GetReport again.
    if (reportBuffer == NULL || *reportBufferSize < sizeof(SGX_Report))
    {
        *reportBufferSize = sizeof(SGX_Report);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(
        _SGX_CreateReport(
            reportData,
            reportDataSize,
            optParams,
            optParamsSize,
            reportBuffer));

    *reportBufferSize = sizeof(SGX_Report);
    result = OE_OK;

done:

    return result;
}

static OE_Result _OE_GetSGXTargetInfo(SGX_TargetInfo* targetInfo)
{
    OE_Result result = OE_UNEXPECTED;
    OE_GetQETargetInfoArgs* args =
        (OE_GetQETargetInfoArgs*)OE_HostCalloc(1, sizeof(*args));
    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        OE_OCall(
            OE_FUNC_GET_QE_TARGET_INFO,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));

    result = args->result;
    if (result == OE_OK)
        *targetInfo = args->targetInfo;

    result = OE_OK;
done:
    if (args)
    {
        OE_SecureZeroFill(args, sizeof(*args));
        OE_HostFree(args);
    }

    return result;
}

static OE_Result _OE_GetQuote(
    const SGX_Report* sgxReport,
    uint8_t* quote,
    uint32_t* quoteSize)
{
    OE_Result result = OE_UNEXPECTED;
    uint32_t argSize = sizeof(OE_GetQETargetInfoArgs);

    // If quote buffer is NULL, then ignore passed in quoteSize value.
    // This treats scenarios where quote == NULL and *quoteSize == large-value
    // as OE_BUFFER_TOO_SMALL.
    if (quote == NULL)
        *quoteSize = 0;

    // Allocate memory for args structure + quote buffer.
    argSize += *quoteSize;

    OE_GetQuoteArgs* args = (OE_GetQuoteArgs*)OE_HostCalloc(1, argSize);
    args->sgxReport = *sgxReport;
    args->quoteSize = *quoteSize;

    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
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

done:
    if (args)
    {
        OE_SecureZeroFill(args, argSize);
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
    OE_Result result = OE_UNEXPECTED;
    SGX_TargetInfo sgxTargetInfo = {0};
    SGX_Report sgxReport = {0};
    uint32_t sgxReportSize = sizeof(sgxReport);
    OE_Report parsedReport;

    // For remote attestation, the Quoting Enclave's target info is used.
    // optParams must not be supplied.
    if (optParams != NULL || optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /*
     * OCall: Get target info from Quoting Enclave.
     * This involves a call to host. The target provided by targetinfo does not
     * need to be trusted because returning a report is not an operation that
     * requires privacy. The trust decision is one of integrity verification
     * on the part of the report recipient.
     */
    OE_CHECK(_OE_GetSGXTargetInfo(&sgxTargetInfo));

    /*
     * Get enclave's local report passing in the quoting enclave's target info.
     */
    OE_CHECK(
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
    OE_CHECK(_OE_GetQuote(&sgxReport, reportBuffer, reportBufferSize));

    /*
     * Check that the entire report body in the returned quote matches the local
     * report.
     */
    if (OE_ParseReport(reportBuffer, *reportBufferSize, &parsedReport) != OE_OK)
        OE_RAISE(OE_UNEXPECTED);

    if (OE_Memcmp(
            parsedReport.enclaveReport,
            &sgxReport.body,
            sizeof(sgxReport.body)) != 0)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;
done:

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

static OE_Result _SafeCopyGetReportArgs(
    uint64_t argIn,
    OE_GetReportArgs* safeArg,
    uint8_t* reportBuffer)
{
    OE_Result result = OE_UNEXPECTED;
    OE_GetReportArgs* unsafeArg = (OE_GetReportArgs*)argIn;

    if (!unsafeArg || !OE_IsOutsideEnclave(unsafeArg, sizeof(*unsafeArg)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy arg to prevent TOCTOU issues.
    // All input fields now lie in enclave memory.
    OE_SecureMemcpy(safeArg, unsafeArg, sizeof(*safeArg));

    if (safeArg->reportBufferSize > OE_MAX_REPORT_SIZE)
        safeArg->reportBufferSize = OE_MAX_REPORT_SIZE;

    // Ensure that output buffer lies outside the enclave.
    if (safeArg->reportBuffer &&
        !OE_IsOutsideEnclave(safeArg->reportBuffer, safeArg->reportBufferSize))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Use output buffer within enclave.
    if (safeArg->reportBuffer)
        safeArg->reportBuffer = reportBuffer;

    result = OE_OK;
done:
    return result;
}

static OE_Result _SafeCopyGetReportArgsOuput(
    OE_GetReportArgs* safeArg,
    uint64_t argIn)
{
    OE_Result result = OE_UNEXPECTED;

    OE_GetReportArgs* unsafeArg = (OE_GetReportArgs*)argIn;

    if (safeArg->result == OE_OK)
    {
        // Perform validation again. The reportBuffer field could have been
        // changed. Use volatile to ensure that the compiler doesn't optimize
        // away the copy.
        uint8_t* volatile hostReportBuffer = unsafeArg->reportBuffer;
        if (!OE_IsOutsideEnclave(hostReportBuffer, safeArg->reportBufferSize))
            OE_RAISE(OE_UNEXPECTED);

        OE_SecureMemcpy(
            hostReportBuffer, safeArg->reportBuffer, safeArg->reportBufferSize);
    }

    unsafeArg->reportBufferSize = safeArg->reportBufferSize;
    unsafeArg->result = safeArg->result;
    result = OE_OK;

done:
    return result;
}

OE_Result _HandleGetReport(uint64_t argIn)
{
    OE_Result result = OE_UNEXPECTED;
    OE_GetReportArgs arg;

    uint8_t reportBuffer[OE_MAX_REPORT_SIZE];

    // Validate and copy args to prevent TOCTOU issues.
    OE_CHECK(_SafeCopyGetReportArgs(argIn, &arg, reportBuffer));

    // Host is not allowed to pass report data. Otherwise, the host can use the
    // enclave to put whatever data it wants in a report. The data field is
    // intended to be used for digital signatures and is not allowed to be
    // tampered with by the host.

    arg.result = OE_GetReport(
        arg.options,
        NULL,
        0,
        (arg.optParamsSize != 0) ? arg.optParams : NULL,
        arg.optParamsSize,
        arg.reportBuffer,
        &arg.reportBufferSize);

    // Copy outputs to host memory.
    OE_CHECK(_SafeCopyGetReportArgsOuput(&arg, argIn));
    result = OE_OK;

done:
    return result;
}
