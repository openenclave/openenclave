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

OE_CHECK_SIZE(sizeof(SGX_ReportData), OE_REPORT_DATA_SIZE);

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

OE_Result _HandleGetSGXReport(uint64_t argIn)
{
    OE_GetSGXReportArgs* arg = (OE_GetSGXReportArgs*)argIn;
    if (!arg || !OE_IsOutsideEnclave(arg, sizeof(*arg)))
        return OE_INVALID_PARAMETER;

    // Copy arg to prevent TOCTOU issues.
    OE_GetSGXReportArgs tmp = *arg;

    // Check that all the supplied objects lie outside the enclave.
    if (tmp.targetInfo &&
        !OE_IsOutsideEnclave(tmp.targetInfo, tmp.targetInfoSize))
        return OE_INVALID_PARAMETER;

    if (tmp.reportData &&
        !OE_IsOutsideEnclave(tmp.reportData, tmp.reportDataSize))
        return OE_INVALID_PARAMETER;

    if (tmp.report && !OE_IsOutsideEnclave(tmp.report, *tmp.reportSize))
        return OE_INVALID_PARAMETER;

    if (tmp.reportSize &&
        !OE_IsOutsideEnclave(tmp.reportSize, sizeof(*tmp.reportSize)))
        return OE_INVALID_PARAMETER;

    arg->result = _OE_GetSGXReport(
        tmp.reportData,
        tmp.reportDataSize,
        tmp.targetInfo,
        tmp.targetInfoSize,
        tmp.report,
        tmp.reportSize);

    return OE_OK;
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
    OE_GetRemoteReportArgs* args = NULL;
    uint32_t argsSize = 0;

    // Perform mimimal validations here; the ones that necessary for making the
    // O_Call.
    // The implementation on the host will do the full validation.

    if (!reportBufferSize)
        OE_THROW(OE_INVALID_PARAMETER);

    // For remote reports, optParams must be null.
    if (optParams != NULL || optParamsSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    if (reportDataSize > OE_REPORT_DATA_SIZE)
        OE_THROW(OE_INVALID_PARAMETER);

    // Allocate args and report buffer immediately following it.
    argsSize = sizeof(OE_GetRemoteReportArgs) + *reportBufferSize;

    args = (OE_GetRemoteReportArgs*)OE_HostCalloc(1, argsSize);
    if (args == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    // Fill args.
    OE_Memcpy(args->reportData, reportData, reportDataSize);
    args->reportDataSize = reportDataSize;
    args->reportBufferSize = *reportBufferSize;

    // Make a re-entrant call to host. The host will call back into the enclave
    // to get the SGX_Report.
    OE_TRY(OE_OCall(OE_FUNC_GET_REMOTE_REPORT, (uint64_t)&args, NULL, 0));

    // Copy out-parameters to enclave memory.
    *reportBufferSize = args->reportBufferSize;
    OE_Memcpy(reportBuffer, args->reportBuffer, *reportBufferSize);
    result = args->result;

OE_CATCH:

    if (args)
    {
        OE_Memset(args, 0, argsSize);
        OE_HostFree(args);
    }

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
