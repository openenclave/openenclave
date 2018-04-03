// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/defs.h>

#ifdef OE_BUILD_ENCLAVE

#include <openenclave/bits/enclavelibc.h>
#include <openenclave/enclave.h>

#define Memset OE_Memset
#define Memcpy OE_Memcpy
#define IsValidMemory(ptr, size) OE_IsOutsideEnclave(ptr, size)

#else

#include <openenclave/host.h>
#include <stdio.h>

#define Memset memset
#define Memcpy memcpy
#define IsValidMemory(ptr, size) true

#endif

static void _OE_ParseSGXReportBody(
    const SGX_ReportBody* reportBody,
    bool remote,
    OE_Report* parsedReport)
{
    Memset(parsedReport, 0, sizeof(OE_Report));

    parsedReport->size = sizeof(OE_Report);
    parsedReport->type = OE_TYPE_SGX;

    /*
     * Parse identity.
     */
    parsedReport->identity.idVersion = 0x0;
    parsedReport->identity.securityVersion = reportBody->isvsvn;

    if (reportBody->attributes.flags & SGX_FLAGS_DEBUG)
        parsedReport->identity.attributes |= OE_REPORT_ATTRIBUTES_DEBUG;
    if (remote)
        parsedReport->identity.attributes |= OE_REPORT_ATTRIBUTES_REMOTE;

    OE_STATIC_ASSERT(
        sizeof(parsedReport->identity.uniqueID) >=
        sizeof(reportBody->mrenclave));
    Memcpy(
        parsedReport->identity.uniqueID, reportBody->mrenclave, OE_SHA256_SIZE);

    OE_STATIC_ASSERT(
        sizeof(parsedReport->identity.authorID) >=
        sizeof(reportBody->mrsigner));
    Memcpy(
        parsedReport->identity.authorID, reportBody->mrsigner, OE_SHA256_SIZE);

    parsedReport->identity.productID[0] = reportBody->isvprodid & 0xFF;
    parsedReport->identity.productID[1] = (reportBody->isvprodid >> 8) & 0xFF;

    /*
     * Set pointer fields.
     */
    parsedReport->reportData = (uint8_t*)&reportBody->reportData;
    parsedReport->reportDataSize = sizeof(SGX_ReportData);
    parsedReport->enclaveReport = (uint8_t*)reportBody;
    parsedReport->enclaveReportSize = sizeof(SGX_ReportBody);
}

OE_Result OE_ParseReport(
    const uint8_t* report,
    uint32_t reportSize,
    OE_Report* parsedReport)
{
    OE_Result result = OE_OK;

    if (report == NULL || parsedReport == NULL ||
        !IsValidMemory(parsedReport, sizeof(OE_Report)))
        OE_THROW(OE_INVALID_PARAMETER);

    if (reportSize == sizeof(SGX_Report))
        _OE_ParseSGXReportBody(
            &((const SGX_Report*)report)->body, false, parsedReport);

    else if (reportSize >= sizeof(SGX_Quote))
        _OE_ParseSGXReportBody(
            &((const SGX_Quote*)report)->report_body, false, parsedReport);

    else
        OE_THROW(OE_INVALID_PARAMETER);

OE_CATCH:
    return result;
}
