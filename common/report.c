// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>

#ifdef OE_BUILD_ENCLAVE

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>

#define Memset OE_Memset
#define Memcpy OE_Memcpy

#else

#include <openenclave/host.h>
#include <stdio.h>

#define Memset memset
#define Memcpy memcpy

#endif

static void _OE_ParseSGXReportBody(
    const SGX_ReportBody* reportBody,
    bool remote,
    OE_Report* parsedReport)
{
    Memset(parsedReport, 0, sizeof(OE_Report));

    parsedReport->size = sizeof(OE_Report);
    parsedReport->type = OE_ENCLAVE_TYPE_SGX;

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
        parsedReport->identity.uniqueID,
        reportBody->mrenclave,
        sizeof(reportBody->mrenclave));

    OE_STATIC_ASSERT(
        sizeof(parsedReport->identity.authorID) >=
        sizeof(reportBody->mrsigner));
    Memcpy(
        parsedReport->identity.authorID,
        reportBody->mrsigner,
        sizeof(reportBody->mrsigner));

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
    const SGX_Report* sgxReport = NULL;
    const SGX_Quote* sgxQuote = NULL;
    OE_Result result = OE_OK;

    if (report == NULL || parsedReport == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportSize == sizeof(SGX_Report))
    {
        sgxReport = (const SGX_Report*)report;
        _OE_ParseSGXReportBody(&sgxReport->body, false, parsedReport);
    }
    else if (reportSize >= sizeof(SGX_Quote))
    {
        sgxQuote = (const SGX_Quote*)report;
        _OE_ParseSGXReportBody(&sgxQuote->report_body, true, parsedReport);
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

done:
    return result;
}
