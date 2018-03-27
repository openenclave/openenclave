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
    if (!arg || OE_IsWithinEnclave(arg, sizeof(*arg)))
        return OE_INVALID_PARAMETER;

    // Copy arg to prevent TOCTOU issues.
    OE_GetSGXReportArgs tmp = *arg;

    // Check that all the supplied objects lie outside the enclave.
    if (tmp.targetInfo &&
        OE_IsWithinEnclave(tmp.targetInfo, tmp.targetInfoSize))
        return OE_INVALID_PARAMETER;

    if (tmp.reportData &&
        OE_IsWithinEnclave(tmp.reportData, tmp.reportDataSize))
        return OE_INVALID_PARAMETER;

    if (tmp.report && OE_IsWithinEnclave(tmp.report, *tmp.reportSize))
        return OE_INVALID_PARAMETER;

    if (tmp.reportSize &&
        OE_IsWithinEnclave(tmp.reportSize, sizeof(*tmp.reportSize)))
        return OE_INVALID_PARAMETER;

    return _OE_GetSGXReport(
        tmp.reportData,
        tmp.reportDataSize,
        tmp.targetInfo,
        tmp.targetInfoSize,
        tmp.report,
        tmp.reportSize);
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
    // TODO: Call into host for remote attestation
    if (options & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
    {
        return OE_UNSUPPORTED;
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
