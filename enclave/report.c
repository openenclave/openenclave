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

OE_Result SGX_CreateReport(
    const SGX_TargetInfo* targetInfo,
    const SGX_ReportData* reportData,
    SGX_Report* report)
{
    OE_Result result = OE_UNEXPECTED;

    // Allocate aligned objects as required by EREPORT instruction.
    SGX_TargetInfo ti __attribute__((aligned(512))) = {};
    SGX_ReportData rd __attribute__((aligned(128))) = {};
    SGX_Report r __attribute__((aligned(512))) = {};

    /* Reject invalid parameters (reportData may be null) */
    if (!targetInfo || !report)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_Memcpy(&ti, targetInfo, sizeof(SGX_TargetInfo));
    OE_Memcpy(&rd, reportData, sizeof(SGX_ReportData));
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

OE_CHECK_SIZE(sizeof(SGX_ReportData), OE_REPORT_DATA_SIZE);

OE_Result _HandleGetSGXReport(uint64_t argIn)
{
    if (!argIn)
        return OE_INVALID_PARAMETER;

    // Copy argIn to prevent TOCTOU issues.
    OE_GetSGXReportArgs args;
    OE_Memcpy(&args, (OE_GetSGXReportArgs*)argIn, sizeof(args));

    if (!args.targetInfo || !args.reportData || !args.report)
        return OE_INVALID_PARAMETER;

    return SGX_CreateReport(args.targetInfo, args.reportData, args.report);
}
