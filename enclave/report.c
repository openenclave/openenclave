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
    SGX_TargetInfo* ti = NULL;
    SGX_ReportData* rd = NULL;
    SGX_Report* r = NULL;
    SGX_Report* r1 = NULL;

    /* Reject invalid parameters (reportData may be null) */
    if (!targetInfo || !report)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Align TARGET INFO on 512 byte boundary */
    {
        if (!(ti = (SGX_TargetInfo*)OE_StackAlloc(sizeof(SGX_TargetInfo), 512)))
            OE_THROW(OE_OUT_OF_MEMORY);

        OE_Memcpy(ti, targetInfo, sizeof(SGX_TargetInfo));
    }

    /* Align REPORT DATA on 128 byte boundary (if not null) */
    if (reportData)
    {
        if (!(rd = (SGX_ReportData*)OE_StackAlloc(sizeof(SGX_ReportData), 128)))
            OE_THROW(OE_OUT_OF_MEMORY);

        OE_Memcpy(rd, reportData, sizeof(SGX_ReportData));
    }

    /* Align REPORT on 512 byte boundary */
    {
        if (!(r = (SGX_Report*)OE_StackAlloc(sizeof(SGX_Report), 512)))
            OE_THROW(OE_OUT_OF_MEMORY);

        OE_Memset(r, 0, sizeof(SGX_Report));
    }

    /* Align REPORT on 512 byte boundary */
    {
        if (!(r1 = (SGX_Report*)OE_StackAlloc(sizeof(SGX_Report), 512)))
            OE_THROW(OE_OUT_OF_MEMORY);

        OE_Memset(r1, 0, sizeof(SGX_Report));
    }

    /* Invoke EREPORT instruction */
    asm volatile(
        "ENCLU"
        :
        : "a"(ENCLU_EREPORT), "b"(ti), "c"(rd), "d"(r)
        : "memory");

    /* Copy REPORT to caller's buffer */
    OE_Memcpy(report, r, sizeof(SGX_Report));

    result = OE_OK;

OE_CATCH:

    if (ti)
        OE_Memset(ti, 0, sizeof(SGX_TargetInfo));

    if (rd)
        OE_Memset(rd, 0, sizeof(SGX_ReportData));

    if (r)
        OE_Memset(r, 0, sizeof(SGX_Report));

    return result;
}

OE_CHECK_SIZE(sizeof(SGX_ReportData), OE_REPORT_DATA_SIZE);

OE_Result _HandleGetSGXReport(uint64_t argIn)
{
    OE_GetSGXReportArgs* args = (OE_GetSGXReportArgs*)argIn;

    if (!args)
        return OE_INVALID_PARAMETER;

    if (!args->targetInfo || !args->reportData || !args->report)
        return OE_INVALID_PARAMETER;

    return SGX_CreateReport(args->targetInfo, args->reportData, args->report);
}
