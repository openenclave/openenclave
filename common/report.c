// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include "common.h"

static void _oe_parse_sgx_report_body(
    const sgx_report_body_t* reportBody,
    bool remote,
    oe_report_t* parsedReport)
{
    memset(parsedReport, 0, sizeof(oe_report_t));

    parsedReport->size = sizeof(oe_report_t);
    parsedReport->type = OE_ENCLAVE_TYPE_SGX;

    /*
     * Parse identity.
     */
    parsedReport->identity.id_version = 0x0;
    parsedReport->identity.security_version = reportBody->isvsvn;

    if (reportBody->attributes.flags & SGX_FLAGS_DEBUG)
        parsedReport->identity.attributes |= OE_REPORT_ATTRIBUTES_DEBUG;

    if (remote)
        parsedReport->identity.attributes |= OE_REPORT_ATTRIBUTES_REMOTE;

    OE_STATIC_ASSERT(
        sizeof(parsedReport->identity.unique_id) >=
        sizeof(reportBody->mrenclave));
    memcpy(
        parsedReport->identity.unique_id,
        reportBody->mrenclave,
        sizeof(reportBody->mrenclave));

    OE_STATIC_ASSERT(
        sizeof(parsedReport->identity.signer_id) >=
        sizeof(reportBody->mrsigner));

    memcpy(
        parsedReport->identity.signer_id,
        reportBody->mrsigner,
        sizeof(reportBody->mrsigner));

    parsedReport->identity.product_id[0] = reportBody->isvprodid & 0xFF;
    parsedReport->identity.product_id[1] = (reportBody->isvprodid >> 8) & 0xFF;

    /*
     * Set pointer fields.
     */
    parsedReport->report_data = (uint8_t*)&reportBody->report_data;
    parsedReport->report_data_size = sizeof(sgx_report_data_t);
    parsedReport->enclave_report = (uint8_t*)reportBody;
    parsedReport->enclave_report_size = sizeof(sgx_report_body_t);
}

oe_result_t oe_parse_report(
    const uint8_t* report,
    size_t reportSize,
    oe_report_t* parsedReport)
{
    const sgx_report_t* sgxReport = NULL;
    const sgx_quote_t* sgxQuote = NULL;
    oe_report_header_t* header = (oe_report_header_t*)report;
    oe_result_t result = OE_FAILURE;

    if (report == NULL || parsedReport == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportSize < sizeof(oe_report_header_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (header->version != OE_REPORT_HEADER_VERSION)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (header->report_size + sizeof(oe_report_header_t) != reportSize)
        OE_RAISE(OE_FAILURE);

    if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        sgxReport = (const sgx_report_t*)header->report;
        _oe_parse_sgx_report_body(&sgxReport->body, false, parsedReport);
        result = OE_OK;
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        sgxQuote = (const sgx_quote_t*)header->report;
        _oe_parse_sgx_report_body(&sgxQuote->report_body, true, parsedReport);
        result = OE_OK;
    }
    else
    {
        OE_RAISE(OE_REPORT_PARSE_ERROR);
    }

done:
    return result;
}
