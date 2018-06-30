// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>

#ifdef OE_BUILD_ENCLAVE

#include <openenclave/enclave.h>
#include <openenclave/internal/corelibc/string.h>

#define Memset oe_memset
#define Memcpy oe_memcpy

#else

#include <openenclave/host.h>
#include <stdio.h>

#define Memset memset
#define Memcpy memcpy

#endif

static void _oe_parse_sgx_report_body(
    const sgx_report_body_t* reportBody,
    bool remote,
    oe_report_t* parsedReport)
{
    Memset(parsedReport, 0, sizeof(oe_report_t));

    parsedReport->size = sizeof(oe_report_t);
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
    parsedReport->reportDataSize = sizeof(sgx_report_data_t);
    parsedReport->enclaveReport = (uint8_t*)reportBody;
    parsedReport->enclaveReportSize = sizeof(sgx_report_body_t);
}

oe_result_t oe_parse_report(
    const uint8_t* report,
    uint32_t reportSize,
    oe_report_t* parsedReport)
{
    const sgx_report_t* sgxReport = NULL;
    const sgx_quote_t* sgxQuote = NULL;
    oe_result_t result = OE_OK;

    if (report == NULL || parsedReport == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportSize == sizeof(sgx_report_t))
    {
        sgxReport = (const sgx_report_t*)report;
        _oe_parse_sgx_report_body(&sgxReport->body, false, parsedReport);
    }
    else if (reportSize >= sizeof(sgx_quote_t))
    {
        sgxQuote = (const sgx_quote_t*)report;
        _oe_parse_sgx_report_body(&sgxQuote->report_body, true, parsedReport);
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

done:
    return result;
}
